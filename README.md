# QuestBoss

A game-style daily planner for kids and teens: quests, XP, levels, coins, streaks, badges, skins and parent-approved rewards. Accounts are real (server-side storage), with child and adult account types and a Family area.

- Zero dependencies, Node.js >= 18
- Data in `data/db.json` (atomic writes), passwords hashed with scrypt, HttpOnly session cookie
- Family: adults create child accounts, assign tasks to them (optionally with parent approval), confirm completed tasks and manage the children's rewards. Child accounts that belong to a family have no PIN; self-registered child accounts keep the PIN
- App languages: English (default), German, French, Italian, Spanish, Polish (switch via the gear menu)

## Install on Pterodactyl

1. Import `egg/egg-questboss.json` (Admin -> Nests -> Import Egg), or use the raw URL of that file.
2. Create a server with the egg. Variables:
   - `GITHUB_REPO` - `owner/repo` to download from (default: Mit-Zwei-T-Apps/QuestBoss)
   - `RELEASE_TAG` - `latest` or a tag such as `v1.0.0`
   - `ALLOW_REGISTER`, `ADMIN_USER`, `ADMIN_PASSWORD`, `COOKIE_SECURE`, `TRUST_PROXY`, `MAX_USERS`
3. Start the server. On first start an `admin` account is created with a random password, printed in the console and stored in `data/admin-initial-password.txt`. Log in and you will be forced to set a new password (the file is then deleted).
4. Update: set `RELEASE_TAG` (or keep `latest`) and run **Reinstall**. The `data/` folder is kept.

The installer verifies `questboss.tar.gz.sha256` and rejects unsafe archives.

## Run locally

    node server.js        # http://localhost:3000

## Environment variables

| Variable | Default | Meaning |
|---|---|---|
| `SERVER_PORT` / `PORT` | 3000 | Listen port |
| `HOST` | 0.0.0.0 | Listen address |
| `DATA_DIR` | `./data` | Storage directory |
| `ALLOW_REGISTER` | true | Allow self-registration |
| `ADMIN_USER` | admin | Admin username |
| `ADMIN_PASSWORD` | random | Initial admin password (re-applied only when the value changes) |
| `COOKIE_SECURE` | false | Set `true` behind HTTPS |
| `TRUST_PROXY` | false | Set `true` to use `X-Forwarded-For` for rate limiting |
| `MAX_USERS` | 1000 | User limit |

Run behind an HTTPS reverse proxy for real use, with `COOKIE_SECURE=true` and `TRUST_PROXY=true`.

## Releasing

1. Bump `version` in `package.json`.
2. `git tag vX.Y.Z && git push --tags`

The GitHub Action builds `questboss.tar.gz` plus its `.sha256` and publishes a release. Regenerate the egg for a fork with `python3 scripts/make_egg.py OWNER/REPO --author you@example.com`.

## Note

The in-app "small reward" link (`PP` constant in `public/index.html`) points to the original developer. Set it to your own link, or to an empty string to hide the section.

## Credits

Created by Matteo Mit Zwei T and M4rcu5, with Claude.
