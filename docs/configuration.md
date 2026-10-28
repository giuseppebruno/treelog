# Configuration reference

This page lists every setting Treelog reads. The everyday ones are in the [README](../README.md) and in [`.env.example`](../.env.example); the defaults suit most installations. The settings marked **advanced** below tune memory, timing and detection internals: change them only if you have a specific reason, and change one at a time.

All settings are environment variables, read from `.env` (the compose file passes it to the container with `env_file`). After editing `.env`, apply the change with:

```bash
docker compose up -d
```

Empty values are treated as unset, so `NAME=` falls back to the default. Numeric values that cannot be parsed stop the container at startup with a Python error (see `docker compose logs treelog`).

## Compose settings

Read by `docker-compose.yml`, not by the application.

| Variable | Default | Description |
|---|---|---|
| `LOG_DIR` | required | Log directory on the host, mounted read-only on `/logs`. |
| `LOG_GID` | `4` | Group id that can read the logs, added to the container user. |
| `PORT` | `8080` | Dashboard port. Published on `127.0.0.1` only; also read by the application. |
| `TZ` | `UTC` | Timezone of the host writing the logs. Needed to interpret error log timestamps, which carry no UTC offset. |

## Log sources and retention

| Variable | Default | Description |
|---|---|---|
| `ACCESS_LOGS` | `/logs/**/*access*.log*` | Comma-separated globs for access logs. `**` matches subdirectories. |
| `ERROR_LOGS` | `/logs/**/*error*.log*` | Comma-separated globs for error logs. |
| `ACCESS_REGEX` | empty | Custom access log format: regular expression with the named groups `ip`, `ts`, `req`, `status`, `ua` and, optionally, `vhost`. `ts` must look like `10/Oct/2026:13:55:36 +0200`. |
| `RETENTION_HOURS` | `48` | History kept, in hours. The time windows offered by the dashboard never exceed it. |
| `BACKFILL_MB` | `200` | On first start, read at most the last N MB of each file. Compressed `.gz` files are read in full on first start only. |
| `POLL_SECONDS` | `2` | **Advanced.** How often the log files are checked for new lines. |
| `SAVE_EVERY_SECONDS` | `60` | **Advanced.** How often the state is written to disk. Counters and read offsets are saved together, so after a crash the lines written since the last save are simply read again from the logs. |
| `STATE_FILE` | `/data/state.json` | **Advanced.** Where read offsets and counters are stored. Must stay inside the `/data` volume: the rest of the container filesystem is read-only. The geolocation files live in the same directory. |

## Virtual hosts and exclusions

| Variable | Default | Description |
|---|---|---|
| `VHOST_REGEX` | empty | Regular expression applied to the log file path, with a named group `vhost` (or a single group). When empty, the host is taken from the file name (`example.com.access.log` becomes `example.com`) or, for generic names, from the parent directory. A `vhost_combined` access log carries the host in each line and takes precedence. |
| `MAX_VHOSTS` | `50` | **Advanced.** Maximum number of distinct virtual hosts tracked. Further hosts are grouped as `(other vhosts)`. |
| `IGNORE_IPS` | empty | Comma-separated source addresses to ignore (uptime monitors, your own IP). |
| `IGNORE_REGEX` | empty | Regular expression matched against the request line; matching requests are ignored. |

## Memory and resolution (advanced)

Treelog keeps counters in time buckets, one set per virtual host. These settings bound how much memory that takes. The defaults keep it around 20 MB; raising them increases both memory and the size of the dashboard response.

| Variable | Default | Description |
|---|---|---|
| `BUCKET_SECONDS` | `600` for 48 h | Width of a time bucket. By default it is chosen so that the retention holds about 288 buckets (never below 600 s, in multiples of 5 minutes). A smaller value gives a finer time axis and uses more memory. Existing history keeps its old resolution, it is not recomputed. |
| `MAX_KEYS_PER_BUCKET` | `200` | Distinct entries kept per bucket and virtual host for attacks (source IPs get three quarters of it, error log messages a third, 5xx on benign requests a fifth). Beyond the limit, entries are counted under `(other)`: totals stay exact, detail is lost. |
| `TOP_ROWS` | `800` | Maximum rows per dataset (attacks, error log, 5xx) sent to the dashboard; for source IPs it is the maximum number of distinct addresses. Whatever exceeds the limit is grouped as `(other)` and totals stay exact. It does not limit how many log lines are read. With many virtual hosts each host adds its own rows, so a higher value shows more detail at the cost of a larger response. |

## Offending IP detection (advanced)

Behaviour is evaluated per source address over a sliding window. Lower thresholds report more addresses and more false positives, for example several users behind one NAT.

| Variable | Default | Description |
|---|---|---|
| `BEHAVIOR_WINDOW_MINUTES` | `10` | Length of the window. |
| `SCAN_MIN` | `30` | Distinct paths answered with 4xx within the window: enumeration. |
| `BRUTE_MIN` | `15` | Login `POST`s (or `401` responses) within the window: credential brute force. A `POST` counts as a login when the path contains `login` or `signin`, or is `xmlrpc.php`, `/auth`, `/authenticate`, `j_security_check` or the Joomla `/administrator/` login. Generic paths such as `/admin`, `/account` or `/token` are not counted. |
| `FLOOD_MIN` | `600` | Total requests from one address within the window: flood. |
| `ATTACK_MIN` | `20` | Hostile requests from one address within the window: repeated attacks. |
| `MAX_TRACKED_IPS` | `5000` | Addresses tracked at once. When full, idle ones are dropped first. |

## Alerts

Channels. Set at least one to receive notifications.

| Variable | Default | Description |
|---|---|---|
| `ALERT_NAME` | empty | Prefix for notification titles, useful with several servers. |
| `ALERT_DASHBOARD_URL` | empty | Link added to notifications. |
| `ALERT_NTFY_URL`, `ALERT_NTFY_TOKEN` | empty | ntfy topic URL and optional access token. |
| `ALERT_TELEGRAM_TOKEN`, `ALERT_TELEGRAM_CHAT_ID` | empty | Telegram bot token and destination chat. Both are required. |
| `ALERT_TELEGRAM_API` | `https://api.telegram.org` | **Advanced.** Telegram API endpoint, for a self-hosted Bot API server or a proxy. |
| `ALERT_WEBHOOK_URL`, `ALERT_WEBHOOK_SECRET` | empty | Generic webhook. With a secret, the body is signed with HMAC-SHA256 in `X-Treelog-Signature`. |

Rules and thresholds, evaluated over the last `ALERT_WINDOW_MINUTES`.

| Variable | Default | Description |
|---|---|---|
| `ALERT_RULES` | `server_errors,exposed,error_rate,spike` | Enabled rules. Also available: `silence`, `offenders`. |
| `ALERT_WINDOW_MINUTES` | `10` | Window over which the rules are evaluated. |
| `ALERT_COOLDOWN_MINUTES` | `60` | Minimum time between repeated notifications for the same rule. |
| `ALERT_NOTIFY_RESOLVED` | `1` | Send a "resolved" notification when a condition clears (`1`, `true`, `yes` or `on`; anything else disables it). |
| `ALERT_EVAL_SECONDS` | `30` | **Advanced.** How often the rules are evaluated. A condition clears after two consecutive evaluations without it. |
| `ALERT_ATTACK_5XX_MIN` | `5` | `server_errors`: hostile requests that received 5xx. |
| `ALERT_EXPOSED_CATEGORIES` | `rce,sqli,traversal` | `exposed`: attack categories that count as high risk. Others: `xss`, `probe`, `scanner`, `malformed`. |
| `ALERT_EXPOSED_MIN` | `3` | `exposed`: high-risk requests served 2xx. |
| `ALERT_5XX_RATE` | `0.05` | `error_rate`: share of 5xx responses (0.05 is 5%). |
| `ALERT_MIN_REQUESTS` | `50` | `error_rate`: minimum requests in the window before the rate is evaluated. |
| `ALERT_SPIKE_MIN` | `200` | `spike`: minimum hostile requests in the window. |
| `ALERT_SPIKE_FACTOR` | `4` | `spike`: multiple of the previous 24 hour average. Needs at least 3 hours of history. |
| `ALERT_SILENCE_MINUTES` | `0` | `silence`: minutes without new access log lines. `0` disables the rule. |

## IP geolocation

| Variable | Default | Description |
|---|---|---|
| `IPINFO_TOKEN` | empty | IPinfo access token. Geolocation is off without it. |
| `GEO_PROVIDER` | `auto` | `api`: per-address lookups (source IPs are sent to IPinfo). `mmdb`: local database downloaded and refreshed by Treelog. `off`: disabled. `auto`: `api` if a token is set, otherwise `off`. |
| `GEO_UPDATE_HOURS` | `168` | **Advanced.** `mmdb`: age after which the local database is downloaded again. |
| `GEO_API_RPS` | `10` | **Advanced.** `api`: maximum lookups per second. |
| `GEO_CACHE_MAX` | `50000` | **Advanced.** `api`: addresses kept in the lookup cache. |
| `GEO_CACHE_FILE` | `/data/geo_cache.json` | **Advanced.** `api`: where the cache is saved. Keep it inside `/data`. |
| `GEO_API_URL`, `GEO_DB_URL` | IPinfo Lite endpoints | **Advanced.** Override only for a mirror or proxy that speaks the same protocol. |

## Dashboard access

| Variable | Default | Description |
|---|---|---|
| `DASH_USER`, `DASH_PASS` | empty | HTTP basic authentication. Set both. Use it behind a TLS reverse proxy: credentials travel in clear over plain HTTP. |
