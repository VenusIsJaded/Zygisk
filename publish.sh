#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# publish.sh — push this repo to GitHub.
#
# WHY THIS SCRIPT EXISTS:
# The original author of this code did not have GitHub credentials in
# the build sandbox. The repo is fully prepared locally (commits are
# in place, .gitignore is set up, CI workflow is in place). All that
# remains is for the user to push to the existing Zygisk repo at
# https://github.com/VenusIsJaded/Zygisk.
#
# USAGE:
#   ./publish.sh                           # use HTTPS + your PAT
#   ./publish.sh --ssh                     # use SSH
#   ./publish.sh --repo VenusIsJaded/Zygisk  # specify the repo
#   ./publish.sh --remote my-fork          # use an existing remote
#
# STEP-BY-STEP (first time):
#
# 1. The GitHub repo already exists:
#    https://github.com/VenusIsJaded/Zygisk
#    It is a public repo, default branch `main`. If you are running
#    this script from a fresh clone, you don't need to do anything
#    here; the `origin` remote is already configured.
#
# 2. Authenticate:
#    - PAT: create a Personal Access Token at
#      https://github.com/settings/tokens (classic, `repo` scope).
#      Store it in your environment:
#        export GH_TOKEN=<your_PAT>
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
# User navigation preferences must not change command-substitution output.
unset CDPATH

# Repo root (the directory this script lives in).
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$REPO_ROOT"

# Defaults.
PROTOCOL="https"           # https or ssh
REPO=""                    # e.g. VenusIsJaded/Zygisk
REMOTE_NAME="origin"       # name of the git remote to use/push to
BRANCH=""                  # default to the current branch
PROTOCOL_SET=0

# Parse args.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --repo|--remote|--branch)
            if [[ $# -lt 2 || -z "$2" || "$2" == -* ]]; then
                echo "publish.sh: $1 requires a value" >&2
                exit 2
            fi ;;
    esac
    case "$1" in
        --ssh)        PROTOCOL="ssh"; PROTOCOL_SET=1; shift;;
        --https)      PROTOCOL="https"; PROTOCOL_SET=1; shift;;
        --repo)       REPO="$2"; shift 2;;
        --remote)     REMOTE_NAME="$2"; shift 2;;
        --branch)     BRANCH="$2"; shift 2;;
        -h|--help)
            sed -n '1,/^set -euo pipefail/p' "$REPO_ROOT/publish.sh" | sed 's/^#//' | sed '1,/^$/d'
            exit 0
            ;;
        *)
            echo "publish.sh: unknown option: $1" >&2
            exit 2
            ;;
    esac
done

# Hooks and wrapper scripts can inherit another checkout's Git context.
# Changing directory does not override these variables: refuse rather than
# silently pushing a different repository or changing its remote settings.
for git_context in GIT_DIR GIT_WORK_TREE GIT_COMMON_DIR GIT_NAMESPACE; do
    if [[ -n "${!git_context:-}" ]]; then
        echo "publish.sh: unset $git_context before publishing this checkout." >&2
        exit 2
    fi
done

# Sanity: are we in a git repo?
if ! git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
    echo "publish.sh: not in a git repo. Run from the project root." >&2
    exit 1
fi

# Sanity: is there at least one commit?
if ! git rev-parse HEAD >/dev/null 2>&1; then
    echo "publish.sh: no commits yet. Run 'git commit' first." >&2
    exit 1
fi

# A fixed main default can report success while leaving the user's changes
# unpublished on a feature branch. Detached checkouts need an explicit choice.
if [[ -z "$BRANCH" ]]; then
    BRANCH="$(git symbolic-ref --quiet HEAD)" || {
        echo "publish.sh: detached HEAD; pass --branch BRANCH." >&2
        exit 1
    }
fi

# Fully qualify both ends: an explicit branch can share its name with a tag.
BRANCH="${BRANCH#refs/heads/}"
if ! git check-ref-format "refs/heads/$BRANCH"; then
    echo "publish.sh: invalid branch name: $BRANCH" >&2
    exit 2
fi

# Validate the source before changing persistent remote configuration. A typo
# must not repoint the remote and only then fail in git push.
if ! git rev-parse --verify "refs/heads/$BRANCH^{commit}" >/dev/null 2>&1; then
    echo "publish.sh: local branch does not exist: $BRANCH" >&2
    exit 2
fi

# Mirror pushes are incompatible with the branch-only refspec below. Reject
# before repointing the remote, rather than failing after persistent changes.
if [[ "$(git config --bool --get "remote.$REMOTE_NAME.mirror" || true)" == true ]]; then
    echo "publish.sh: mirror remotes cannot be used for branch-only publishing." >&2
    exit 2
fi

# Explicit repository/transport options must also apply to existing remotes.
REMOTE_URL="$(git remote get-url "$REMOTE_NAME" 2>/dev/null || true)"
if [[ -z "$REMOTE_URL" && -z "$REPO" ]]; then
    echo "publish.sh: no remote named '$REMOTE_NAME'." >&2
    echo "publish.sh: pass --repo USER/REPO (e.g. --repo VenusIsJaded/Zygisk)." >&2
    exit 1
fi
if [[ -n "$REPO" || $PROTOCOL_SET -eq 1 ]]; then
    # Multi-valued pushurl settings inherited from global/include/command
    # configuration cannot be overridden by editing this repository alone.
    # Refuse before changing either URL, rather than leave a half-repointed remote.
    # Without pushurl Git pushes to every configured url, not only get-url's
    # first result. Inherited url values cannot be removed by a local rewrite.
    all_urls="$(git config --get-all "remote.$REMOTE_NAME.url" || true)"
    local_urls="$(git config --local --get-all "remote.$REMOTE_NAME.url" || true)"
    if [[ "$all_urls" != "$local_urls" ]]; then
        echo "publish.sh: inherited remote URLs must be removed before changing destinations." >&2
        exit 2
    fi
    all_push_urls="$(git config --get-all "remote.$REMOTE_NAME.pushurl" || true)"
    local_push_urls="$(git config --local --get-all "remote.$REMOTE_NAME.pushurl" || true)"
    if [[ "$all_push_urls" != "$local_push_urls" ]]; then
        echo "publish.sh: inherited push URLs must be removed before changing destinations." >&2
        exit 2
    fi
fi
if [[ -z "$REPO" && $PROTOCOL_SET -eq 1 ]]; then
    # Fetch may name upstream while pushes go to the contributor's fork.
    REMOTE_URL="$(git remote get-url --push --all "$REMOTE_NAME")"
    if [[ "$REMOTE_URL" == *$'\n'* ]]; then
        echo "publish.sh: multiple push destinations; pass --repo OWNER/REPO explicitly." >&2
        exit 2
    fi
    case "$REMOTE_URL" in
        https://github.com/*) REPO="${REMOTE_URL#https://github.com/}" ;;
        git@github.com:*) REPO="${REMOTE_URL#git@github.com:}" ;;
        ssh://git@github.com/*) REPO="${REMOTE_URL#ssh://git@github.com/}" ;;
        *) echo "publish.sh: transport conversion requires a GitHub remote or --repo." >&2
           exit 2 ;;
    esac
fi
if [[ -n "$REPO" ]]; then
    REPO="${REPO%.git}"
    if [[ ! "$REPO" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
       [[ "${REPO%%/*}" == . || "${REPO%%/*}" == .. ||
          "${REPO#*/}" == . || "${REPO#*/}" == .. ]]; then
        echo "publish.sh: --repo must be OWNER/REPO (optional .git suffix)." >&2
        exit 2
    fi
    if [[ "$PROTOCOL" == "ssh" ]]; then
        TARGET_URL="git@github.com:$REPO.git"
    else
        TARGET_URL="https://github.com/$REPO.git"
    fi
    if [[ -z "$REMOTE_URL" ]]; then
        git remote add "$REMOTE_NAME" "$TARGET_URL"
    else
        # set-url fails with multiple URL values; even when the first value
        # already matches, secondary URLs remain additional push destinations.
        git config --replace-all "remote.$REMOTE_NAME.url" "$TARGET_URL"
    fi
    # Git gives pushurl precedence over url, including multiple destinations.
    # Explicit destination/transport selection must replace that override too.
    if git config --get-all "remote.$REMOTE_NAME.pushurl" >/dev/null; then
        git config --unset-all "remote.$REMOTE_NAME.pushurl"
    fi
    REMOTE_URL="$TARGET_URL"
fi

# Push.
echo "publish.sh: pushing $BRANCH to $REMOTE_NAME ($REMOTE_URL)"
git push --no-follow-tags -u "$REMOTE_NAME" "refs/heads/$BRANCH:refs/heads/$BRANCH"

# Final status.
echo
echo "publish.sh: done."
echo "publish.sh: your repo is at: $(git remote get-url "$REMOTE_NAME" | sed 's/\.git$//')"
