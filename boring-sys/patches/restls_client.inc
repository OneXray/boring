// Owned, opt-in Restls hooks. This file is included inside BoringSSL's namespace
// by handshake_client.cc; it is not a second TLS implementation. Cryptographic
// key agreement, certificate signatures, record AEAD, transcripts and Finished
// all remain in the native TLS engine. The supplied callback hashes public bytes
// with the official caller-owned keyed BLAKE3 implementation.

static bool restls_hash(SSL *ssl, Span<const uint8_t> input, uint8_t out[32]) {
  if (!ssl->config || !ssl->config->restls_client || input.size() > 65536 ||
      !ssl->config->restls_client->hash(ssl, input.data(), input.size(), out)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_INTERNAL_ERROR);
    return false;
  }
  return true;
}

static constexpr uint16_t kRestls12Groups[] = {
    SSL_GROUP_X25519, SSL_GROUP_SECP256R1, SSL_GROUP_SECP384R1};

static bool restls_prepare_client_hello(SSL_HANDSHAKE *hs) {
  SSL *const ssl = hs->ssl;
  if (!hs->config->restls_client) {
    return true;
  }
  if (SSL_is_dtls(ssl) || SSL_is_quic(ssl) || ssl->server ||
      ssl->enable_early_data || ssl->s3->initial_handshake_complete ||
      hs->min_version < TLS1_2_VERSION || hs->max_version > TLS1_3_VERSION ||
      hs->config->reality_client || hs->config->shadow_tls_v3 ||
      hs->config->jls_client || hs->selected_ech_config ||
      !hs->config->client_ech_config_list.empty() || hs->pake_prover ||
      (SSL_get_mode(ssl) & SSL_MODE_ENABLE_FALSE_START)) {
    OPENSSL_PUT_ERROR(SSL, ERR_R_SHOULD_NOT_HAVE_BEEN_CALLED);
    return false;
  }
  if (hs->restls_hello_prepared) {
    return true;
  }
  hs->session_id.ResizeForOverwrite(32);
  if (!RAND_bytes(hs->session_id.data(), hs->session_id.size())) {
    return false;
  }

  uint8_t digest[32];
  if (hs->config->restls_client->version_hint == TLS1_3_VERSION) {
    // key_share_bytes contains every encoded share, including GREASE. Parsing
    // removes only the length prefixes, as required by the Restls protocol.
    ScopedCBB input;
    if (!CBB_init(input.get(), hs->key_share_bytes.size())) {
      return false;
    }
    CBS shares(hs->key_share_bytes);
    while (CBS_len(&shares) != 0) {
      uint16_t group;
      CBS public_key;
      if (!CBS_get_u16(&shares, &group) ||
          !CBS_get_u16_length_prefixed(&shares, &public_key) ||
          !CBB_add_u16(input.get(), group) ||
          !CBB_add_bytes(input.get(), CBS_data(&public_key), CBS_len(&public_key))) {
        return false;
      }
    }
    for (const auto &psk : hs->pre_shared_keys) {
      auto identity = ssl_pre_shared_key_identity(psk);
      if (!CBB_add_bytes(input.get(), identity.data(), identity.size())) {
        return false;
      }
    }
    if (!restls_hash(ssl, Span(CBB_data(input.get()), CBB_len(input.get())), digest)) {
      return false;
    }
    OPENSSL_memcpy(hs->session_id.data(), digest, 16);
  } else {
    const bool ticket = ssl->session && !ssl->session->ticket.empty();
    static const size_t kThreeSlots[] = {0, 11, 22, 32};
    static const size_t kFourSlots[] = {0, 8, 16, 24, 32};
    const size_t *slots = ticket ? kFourSlots : kThreeSlots;
    for (size_t i = 0; i < 3; ++i) {
      auto &key = hs->restls_eager_keys[i];
      key = SSLKeyShare::Create(kRestls12Groups[i]);
      ScopedCBB public_key;
      if (!key || !CBB_init(public_key.get(), 128) ||
          !key->Generate(public_key.get()) ||
          !CBBFinishArray(public_key.get(), &hs->restls_eager_public[i]) ||
          !restls_hash(ssl, hs->restls_eager_public[i], digest)) {
        return false;
      }
      OPENSSL_memcpy(hs->session_id.data() + slots[i], digest,
                     slots[i + 1] - slots[i]);
    }
    if (ticket) {
      if (!restls_hash(ssl, ssl->session->ticket, digest)) {
        return false;
      }
      OPENSSL_memcpy(hs->session_id.data() + 24, digest, 8);
    }
  }
  OPENSSL_cleanse(digest, sizeof(digest));
  hs->restls_hello_prepared = true;
  return true;
}

static bool restls_client_key_exchange(SSL_HANDSHAKE *hs, CBB *public_key,
                                       Array<uint8_t> *secret, uint8_t *alert) {
  for (size_t i = 0; i < 3; ++i) {
    if (hs->new_session->group_id != kRestls12Groups[i]) {
      continue;
    }
    auto &key = hs->restls_eager_keys[i];
    const auto &wire = hs->restls_eager_public[i];
    const bool ok = key && !wire.empty() &&
        key->Decap(secret, alert, hs->peer_key) &&
        CBB_add_bytes(public_key, wire.data(), wire.size());
    // Discard all private keys once a single negotiated key has been used.
    for (auto &eager : hs->restls_eager_keys) {
      eager.reset();
    }
    return ok;
  }
  *alert = SSL_AD_ILLEGAL_PARAMETER;
  OPENSSL_PUT_ERROR(SSL, SSL_R_WRONG_CURVE);
  return false;
}

bool ssl_restls_open_record(SSL *ssl, Span<uint8_t> *out, uint8_t type,
                            uint16_t version, Span<const uint8_t> header,
                            Span<uint8_t> body) {
  auto &aead = ssl->s3->aead_read_ctx;
  if (!ssl->config || !ssl->config->restls_client ||
      ssl->s3->restls_auth_attempted || aead->is_null_cipher()) {
    return aead->Open(out, type, version, ssl->s3->read_sequence, header, body);
  }
  // This is the first encrypted record only. A failed restored candidate may
  // still be legitimate cover TLS; retry the untouched input at the same TLS
  // sequence number and keep the final handshake gate fail-closed.
  ssl->s3->restls_auth_attempted = true;
  Array<uint8_t> candidate;
  uint8_t mask[32];
  if (!candidate.CopyFrom(body) ||
      !restls_hash(ssl, ssl->s3->server_random, mask)) {
    return false;
  }
  size_t offset = 0;
  const auto *cipher = aead->cipher();
  const bool gcm12 = ssl_protocol_version(ssl) == TLS1_2_VERSION &&
      (cipher->algorithm_enc & (SSL_AES128GCM | SSL_AES256GCM));
  static const uint8_t kZeroNonce[8] = {};
  if (gcm12 && candidate.size() >= 8 &&
      OPENSSL_memcmp(candidate.data(), kZeroNonce, 8) == 0) {
    offset = 8;
  }
  if (candidate.size() < offset + 16) {
    OPENSSL_cleanse(mask, sizeof(mask));
    return aead->Open(out, type, version, ssl->s3->read_sequence, header, body);
  }
  for (size_t i = 0; i < 16; ++i) {
    candidate[offset + i] ^= mask[i];
  }
  OPENSSL_cleanse(mask, sizeof(mask));
  // TLS >=1.2 record AEADs are nonce-explicit or sequence-derived. CBC uses an
  // explicit IV and reinitializes its cipher per Open, so the candidate cannot
  // advance a chained IV. No TLS sequence or transcript has been changed here.
  // The implementation also returns nullptr for an empty error queue, despite
  // its header only mentioning allocation failure. Preserve nonempty queues;
  // a null snapshot of an empty queue is valid and restores by clearing it.
  const bool had_errors = ERR_peek_error() != 0;
  UniquePtr<ERR_SAVE_STATE> errors(ERR_save_state());
  if (had_errors && !errors) {
    return false;
  }
  Span<uint8_t> plaintext;
  if (aead->Open(&plaintext, type, version, ssl->s3->read_sequence, header,
                 Span(candidate.data(), candidate.size()))) {
    const size_t plain_offset = plaintext.data() - candidate.data();
    OPENSSL_memcpy(body.data(), candidate.data(), candidate.size());
    *out = body.subspan(plain_offset, plaintext.size());
    ssl->s3->restls_server_authenticated = true;
    OPENSSL_cleanse(candidate.data(), candidate.size());
    return true;
  }
  OPENSSL_cleanse(candidate.data(), candidate.size());
  ERR_restore_state(errors.get());
  return aead->Open(out, type, version, ssl->s3->read_sequence, header, body);
}
