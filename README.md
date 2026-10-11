# QuestBoss

A game-style daily planner for kids and teens: quests, XP, levels, coins, streaks, badges, skins and parent-approved rewards. Accounts are real (server-side storage), with child and adult account types and a Family area.

- Zero dependencies, Node.js >= 18
- Data in `data/db.json` (atomic writes), passwords hashed with scrypt, HttpOnly session cookie
- Families: adults can create child accounts and invite existing accounts (the invited person must accept). Everyone in a family can assign tasks to each other (optionally needing the assigner's confirmation), has per-person rewards (adults create rewards for themselves and unlock them for individual children; children can only create rewards for others), a shared shopping list and a family scoreboard that adults can dispute for children. Login and registration are real forms, so password managers and browsers can save the credentials.
- Plans: rotating family plans (for example Kitchen) where chores shift to the next person every week or every day; tasks can also be assigned to several people at once
- Lists: personal or family shopping list and a wish list; family members can secretly reserve wishes (the wisher does not see reservations)
- Suggestions: users can send improvement ideas from the settings menu; the admin sees them in the Account tab
- Child accounts created by an adult have no PIN; self-registered child accounts keep the PIN
- App languages: English (default), German, French, Italian, Spanish, Polish (switch via the gear menu)

## Install on Pterodactyl

1. Import `egg/egg-questboss.json` (Admin -> Nests -> Import Egg), or use the raw URL of that file.
2. Create a server with the egg. Variables:
   - `GITHUB_REPO` - `owner/repo` to download from (default: Mit-Zwei-T-Apps/QuestBoss)
   - `RELEASE_TAG` - `latest` or a tag such as `v1.0.0`
   - `ALLOW_REGISTER`, `ADMIN_USER`, `ADMIN_PASSWORD`, `COOKIE_SECURE`, `TRUST_PROXY`, `MAX_USERS`
3. Start the server. On first start an `admin` account is created with a random password, printed in the console and stored in `data/admin-initial-password.txt`. Log in and you will be forced to set a new password (the file is then deleted). If you set `ADMIN_PASSWORD` yourself, no change is forced.
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
| `ADMIN_PASSWORD` | random | Admin password. If set, no password change is forced on first login; if empty, a random one is generated and must be changed on first login. Re-applied only when the value changes |
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
