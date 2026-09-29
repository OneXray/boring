# Triage labels

Before applying these labels, complete the repository label setup below.
Use these exact labels for the canonical triage roles.

| Role | GitHub label | Meaning |
| --- | --- | --- |
| needs-triage | needs-triage | Awaiting maintainer evaluation |
| needs-info | needs-info | Awaiting information from the reporter |
| ready-for-agent | ready-for-agent | Fully specified for agent implementation |
| ready-for-human | ready-for-human | Requires human implementation |
| wontfix | wontfix | Will not be actioned |

When a skill names a role, use its mapped GitHub label.
Update this mapping if the repository's label vocabulary changes.

## Repository label setup

Run before the first triage or wayfinding write, and repeat if required labels
are missing. Stop on any failed command; an authentication, permission or
network error is not an empty label list. If label-management access is missing,
ask a maintainer to complete setup before proceeding.

1. Read every existing repository label:

   ```sh
   gh api --paginate 'repos/OneXray/boring/labels?per_page=100' --jq '.[].name'
   ```

2. Compare that list with the table above and the exact `wayfinder:*` names in
   [Wayfinding](issue-tracker.md#wayfinding). For each missing name, create it
   with its documented purpose:

   ```sh
   gh label create "<missing-label>" --repo OneXray/boring --description "<purpose>"
   ```

   Keep existing labels, colors and descriptions unchanged; omit `--force`.
   Substitute each missing name and purpose before running the command.

3. Read the full list again. Proceed only when every required label exists.
   Repeating setup with a complete label set performs no writes.
