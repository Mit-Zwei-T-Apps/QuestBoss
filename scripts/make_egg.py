#!/usr/bin/env python3
"""Generate egg/egg-questboss.json for a given GitHub repository.

Usage: python3 scripts/make_egg.py OWNER/REPO [--author you@example.com]
"""
import argparse, datetime, json, os, re, sys

INSTALL_SCRIPT = r'''#!/bin/ash
# QuestBoss installation: downloads the release archive from GitHub Releases.
# Program files are overwritten, data/ is kept.
set -eu
DIR="${SERVER_DIR:-/mnt/server}"
REPO="${GITHUB_REPO:-}"
TAG="${RELEASE_TAG:-latest}"
BASE="${GITHUB_BASE:-https://github.com}"
fail() { echo "ERROR: $*" >&2; exit 1; }
echo "$REPO" | grep -Eq '^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$' || fail "GITHUB_REPO must look like owner/repo (got: '$REPO')"
echo "$TAG" | grep -Eq '^[A-Za-z0-9._-]+$' || fail "RELEASE_TAG is invalid (got: '$TAG')"
if [ "$TAG" = "latest" ]; then URL="$BASE/$REPO/releases/latest/download"; else URL="$BASE/$REPO/releases/download/$TAG"; fi
command -v curl >/dev/null 2>&1 || apk add --no-cache curl >/dev/null
TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT
echo "Downloading $URL/questboss.tar.gz"
curl -fsSL --retry 3 -o "$TMP/questboss.tar.gz" "$URL/questboss.tar.gz" || fail "download failed (does the release exist and contain questboss.tar.gz?)"
if curl -fsSL -o "$TMP/questboss.tar.gz.sha256" "$URL/questboss.tar.gz.sha256"; then
  (cd "$TMP" && sha256sum -c questboss.tar.gz.sha256) || fail "checksum mismatch"
else
  echo "WARNING: no checksum file in this release, skipping verification"
fi
tar tzf "$TMP/questboss.tar.gz" | grep -Eq '(^/|(^|/)\.\.(/|$))' && fail "archive contains unsafe paths"
tar tvzf "$TMP/questboss.tar.gz" | grep -Eq '^[lh]' && fail "archive contains links"
mkdir -p "$DIR/data" "$DIR/public"
tar xzf "$TMP/questboss.tar.gz" -C "$DIR"
if [ ! -f "$DIR/server.js" ] || [ ! -f "$DIR/public/index.html" ]; then fail "archive is missing server.js or public/index.html"; fi
echo "QuestBoss installed from $REPO ($TAG)."
'''

def var(name, desc, env, default, rules):
    return {"name": name, "description": desc, "env_variable": env, "default_value": default,
            "user_viewable": True, "user_editable": True, "rules": rules, "field_type": "text"}

def build(repo, author):
    return {
        "_comment": "DO NOT EDIT: FILE GENERATED AUTOMATICALLY BY PTERODACTYL PANEL - PTERODACTYL.IO",
        "meta": {"version": "PTDL_v2",
                 "update_url": f"https://raw.githubusercontent.com/{repo}/main/egg/egg-questboss.json"},
        "exported_at": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S+00:00"),
        "name": "QuestBoss (TagesBoss)",
        "author": author,
        "description": "Mobile, game-style task and appointment planner web app (levels, XP, streaks, parent approval) with user accounts (child/adult), a family area and a default admin account that must change its password on first login. Standalone Node.js server without dependencies. The app is downloaded from GitHub Releases on install; data is stored in data/db.json.",
        "features": None,
        "docker_images": {"Node.js 22": "ghcr.io/parkervcp/yolks:nodejs_22",
                          "Node.js 20": "ghcr.io/parkervcp/yolks:nodejs_20",
                          "Node.js 18": "ghcr.io/parkervcp/yolks:nodejs_18"},
        "file_denylist": [],
        "startup": "node server.js",
        "config": {"files": "{}", "startup": json.dumps({"done": "QuestBoss listening"}), "logs": "{}", "stop": "^C"},
        "scripts": {"installation": {"script": INSTALL_SCRIPT,
                                      "container": "ghcr.io/parkervcp/installers:alpine",
                                      "entrypoint": "ash"}},
        "variables": [
            var("GitHub repository", "Where the app is downloaded from, as owner/repo. Only change this if you want to use a fork.", "GITHUB_REPO", repo, "required|string|max:100|regex:/^[A-Za-z0-9_.-]+\\/[A-Za-z0-9_.-]+$/"),
            var("Release tag", "Which release to install: 'latest' or a specific tag such as v1.0.0. Applied on install/reinstall (your data is kept).", "RELEASE_TAG", "latest", "required|string|max:64|regex:/^[A-Za-z0-9._-]+$/"),
            var("Allow registration", "true = new accounts can be created, false = only existing accounts can log in. The admin can also change this later inside the app.", "ALLOW_REGISTER", "true", "required|string|in:true,false"),
            var("Admin username", "Name of the default admin account that is created on first start.", "ADMIN_USER", "admin", "required|string|min:3|max:20|regex:/^[A-Za-z0-9][A-Za-z0-9_-]+$/"),
            var("Admin password", "Leave empty for a random password (shown in the console and in data/admin-initial-password.txt). If set (at least 8 characters) it is the admin password and no change is forced on first login. Changing this value later resets the admin password.", "ADMIN_PASSWORD", "", "nullable|string|min:8|max:100"),
            var("HTTPS cookies", "Set to true if the site is served over HTTPS (for example behind a reverse proxy).", "COOKIE_SECURE", "false", "required|string|in:true,false"),
            var("Trust reverse proxy", "Set to true if a reverse proxy sets X-Forwarded-For (used for the per-IP login limit).", "TRUST_PROXY", "false", "required|string|in:true,false"),
            var("Maximum accounts", "Upper limit for registered accounts.", "MAX_USERS", "1000", "required|integer|min:1|max:100000"),
        ],
    }

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("repo", help="GitHub repository as OWNER/REPO")
    ap.add_argument("--author", default="noreply@example.com")
    ap.add_argument("--out", default=os.path.join(os.path.dirname(__file__), "..", "egg", "egg-questboss.json"))
    a = ap.parse_args()
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", a.repo):
        sys.exit("repo must look like OWNER/REPO")
    with open(a.out, "w", encoding="utf-8") as f:
        json.dump(build(a.repo, a.author), f, indent=4, ensure_ascii=False)
        f.write("\n")
    print("wrote", os.path.abspath(a.out))

if __name__ == "__main__":
    main()
