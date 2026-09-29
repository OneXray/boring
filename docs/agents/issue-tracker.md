# Issue tracker: GitHub

Issues and specs live in `OneXray/boring`. Use the `gh` CLI.
Explicitly target this fork, regardless of the current directory or
upstream repository metadata.

## Operations

- Publish: `gh issue create --repo OneXray/boring --title "..." --body-file <file>`.
- Read: `gh issue view <number> --repo OneXray/boring --json number,title,body,labels,comments,assignees,state`.
- List all open issues (one JSON object per issue; excludes pull requests):

  ```sh
  gh api --paginate 'repos/OneXray/boring/issues?state=open&per_page=100' \
    --jq '.[] | select(.pull_request == null) | {number,title,labels,assignees}'
  ```

- Comment: `gh issue comment <number> --repo OneXray/boring --body-file <file>`.
- Label: `gh issue edit <number> --repo OneXray/boring --add-label "..."` or `--remove-label "..."`.
- Close: `gh issue close <number> --repo OneXray/boring --comment "..."`.

When a skill says "publish to the issue tracker", create an issue.
When it says "fetch the relevant ticket", read its body, labels and comments.
Retrieve all pages when the operation requires a complete list.

## Pull requests as a triage surface

**PRs as a request surface: no.**

Issues and PRs share a number space. For an ambiguous reference, resolve
its type with `gh pr view <number> --repo OneXray/boring`, falling back
to the issue commands.

## Wayfinding

- Map: one issue labelled `wayfinder:map`, containing Notes,
  Decisions-so-far and Fog.
- Children: link tickets as GitHub sub-issues. If unavailable, use a
  task list in the map and `Part of #<map>` in each child.
  Label children `wayfinder:research`, `wayfinder:prototype`,
  `wayfinder:grilling` or `wayfinder:task`.
- Dependencies: use GitHub's native issue dependencies. Obtain the
  blocker's numeric database ID with
  `gh api repos/OneXray/boring/issues/<blocker> --jq .id`, then add it with
  `gh api --method POST repos/OneXray/boring/issues/<child>/dependencies/blocked_by -F issue_id=<blocker-db-id>`.
  If unavailable, record `Blocked by: #<number>` in the child body.
- Allocation: one user-designated coordinator serializes task allocation.
  It records each issue's unique agent/task owner in the map before dispatch;
  workers start only on their explicit assignment. Confirm unclear ownership
  with the user or coordinator before proceeding.
- Frontier: the coordinator selects the first open, unassigned child in map
  order with all blockers closed and no active allocation.
- Responsibility: the assigned worker records its GitHub account with
  `gh issue edit <number> --repo OneXray/boring --add-assignee @me`
  before implementation. Assignees record responsibility, not an exclusive
  claim; workers sharing an account still need distinct task assignments.
- Resolve: comment with the result, close the ticket, and append a
  summary plus link to the map's Decisions-so-far.
