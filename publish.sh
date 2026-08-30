#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# publish.sh — push this repo to GitHub.
#
# WHY THIS SCRIPT EXISTS:
# The original author of this code did not have GitHub credentials in
# the build sandbox. The repo is fully prepared locally (commits are
# in place, .gitignore is set up, CI workflow is in place). All that
# remains is for the user to:
#
#   1. Create an empty GitHub repo (via the web UI, `gh repo create`,
#      or the API).
#   2. Set up authentication (PAT or SSH key).
#   3. Run this script to push.
#
# USAGE:
#   ./publish.sh                           # use HTTPS + your PAT
#   ./publish.sh --ssh                     # use SSH
#   ./publish.sh --repo user/zygisk_study  # specify the repo
#   ./publish.sh --remote my-fork          # use an existing remote
#
# STEP-BY-STEP (first time):
#
# 1. Create the GitHub repo:
#    - Web: https://github.com/new — name it `zygisk_study`, leave
#      it EMPTY (no README, no LICENSE, no .gitignore; we already
#      have all three). Public or private, your call.
#    - CLI: `gh repo create zygisk_study --public --source=.`
#
# 2. Authenticate:
#    - PAT: create a Personal Access Token at
#      https://github.com/settings/tokens (classic, `repo` scope).
#      Store it in your environment:
#        export GH_TOKEN=ghp_xxxxxxxxxxxxxxxxxxxx
#      Or: paste it when git prompts you for a password.
#    - SSH: add your public key at
#      https://github.com/settings/keys
#      Verify with `ssh -T git@github.com`.
#
# 3. Push:
#    ./publish.sh
#
# The script is idempotent: re-running it just does a `git push` to
# the configured remote, which is a no-op if everything is up-to-date.

set -euo pipefail

# Repo root (the directory this script lives in).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Defaults.
PROTOCOL="https"           # https or ssh
REPO=""                    # e.g. user/zygisk_study
REMOTE_NAME="origin"       # name of the git remote to use/push to
BRANCH="main"              # the branch to push

# Parse args.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --ssh)        PROTOCOL="ssh"; shift;;
        --https)      PROTOCOL="https"; shift;;
        --repo)       REPO="$2"; shift 2;;
        --remote)     REMOTE_NAME="$2"; shift 2;;
        --branch)     BRANCH="$2"; shift 2;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$0" | sed 's/^#//' | sed '1,/^$/d'
            exit 0
            ;;
        *)
            echo "publish.sh: unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# Sanity: are we in a git repo?
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "publish.sh: not in a git repo. Run from the zygisk_study/ root." >&2
    exit 1
fi

# Sanity: is there at least one commit?
if ! git rev-parse HEAD >/dev/null 2>&1; then
    echo "publish.sh: no commits yet. Run 'git commit' first." >&2
    exit 1
fi

# Determine the URL to push to.
REMOTE_URL="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || true)"
if [[ -z "$REMOTE_URL" ]]; then
    # No remote with this name. We need to create one.
    if [[ -z "$REPO" ]]; then
        # Try to guess from `git config user.email` if --repo not given.
        GUESS_USER="$(git config user.email | cut -d@ -f1)"
        echo "publish.sh: no remote named '$REMOTE_NAME'." >&2
        echo "publish.sh: pass --repo USER/REPO (e.g. --repo $GUESS_USER/zygisk_study)." >&2
        exit 1
    fi
    if [[ "$PROTOCOL" == "ssh" ]]; then
        REMOTE_URL="git@github.com:$REPO.git"
    else
        REMOTE_URL="https://github.com/$REPO.git"
    fi
    echo "publish.sh: adding remote $REMOTE_NAME -> $REMOTE_URL"
    git remote add "$REMOTE_NAME" "$REMOTE_URL"
fi

# Push.
echo "publish.sh: pushing $BRANCH to $REMOTE_NAME ($REMOTE_URL)"
git push -u "$REMOTE_NAME" "$BRANCH"

# Final status.
echo
echo "publish.sh: done."
echo "publish.sh: your repo is at: $(git remote get-url "$REMOTE_NAME" | sed 's/\.git$//')"
