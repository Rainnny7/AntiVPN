# AntiVPN

[![CI](https://github.com/Rainnny7/AntiVPN/actions/workflows/ci.yml/badge.svg)](https://github.com/Rainnny7/AntiVPN/actions/workflows/ci.yml)
[![Docker](https://github.com/Rainnny7/AntiVPN/actions/workflows/docker.yml/badge.svg)](https://github.com/Rainnny7/AntiVPN/actions/workflows/docker.yml)
[![Live sources](https://github.com/Rainnny7/AntiVPN/actions/workflows/live-sources.yml/badge.svg)](https://github.com/Rainnny7/AntiVPN/actions/workflows/live-sources.yml)

A self-hosted API that tells you whether an IP address is a VPN, Tor exit, proxy relay, datacenter or known-abusive
network. It is built on free, public data only, and tries hard to **not** flag regular users.

```http
GET /check?ip=89.35.28.131
X-API-Key: <your key>
```

```json
{
  "ip": "89.35.28.131",
  "ipType": 4,
  "risk": 1.0,
  "vpn": true,
  "vpnProvider": true,
  "provider": "NordVPN",
  "tor": false,
  "relay": false,
  "hosting": true,
  "abuse": false,
  "allowlisted": false,
  "blacklists": [],
  "detections": [
    { "source": "nordvpn", "name": "NordVPN", "category": "VPN", "confidence": "CONFIRMED", "range": "89.35.28.131" },
    { "source": "hosting-asn", "name": "M247", "category": "HOSTING", "confidence": "LIKELY", "range": "AS9009" }
  ]
}
```

## How detection works

AntiVPN keeps a set of **sources** in memory, each an upstream list of addresses or CIDR blocks. Every source has a
category (what a match means) and a confidence (how sure we are).

| Source                 | Category | Confidence | Refresh | Data                                                                                          |
|------------------------|----------|------------|---------|-----------------------------------------------------------------------------------------------|
| `nordvpn`              | VPN      | Confirmed  | 6h      | [NordVPN server API](https://api.nordvpn.com/v1/servers)                                      |
| `pia`                  | VPN      | Confirmed  | 1h      | [PIA server list](https://serverlist.piaservers.net/vpninfo/servers/v6)                       |
| `mullvad`              | VPN      | Confirmed  | 6h      | [Mullvad relay API](https://api.mullvad.net/www/relays/all/) (active relays, bridges excluded) |
| `surfshark`            | VPN      | Confirmed  | 1h      | Surfshark cluster hostnames, resolved over DNS and kept for 14 days                           |
| `x4b-vpn`              | VPN      | Likely     | 24h     | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) VPN list                              |
| `tor`                  | Tor      | Confirmed  | 1h      | [Tor bulk exit list](https://check.torproject.org/torbulkexitlist)                            |
| `spamhaus-drop`        | Abuse    | Confirmed  | 12h     | [Spamhaus DROP](https://www.spamhaus.org/blocklists/do-not-route-or-peer/) (IPv4 and IPv6)    |
| `icloud-private-relay` | Relay    | Confirmed  | 24h     | [Apple's egress ranges](https://developer.apple.com/support/prepare-your-network-for-icloud-private-relay/) |
| `aws`                  | Hosting  | Confirmed  | 24h     | [AWS ip-ranges.json](https://ip-ranges.amazonaws.com/ip-ranges.json)                          |
| `gcp`                  | Hosting  | Confirmed  | 24h     | [Google Cloud cloud.json](https://www.gstatic.com/ipranges/cloud.json)                        |
| `cloudflare`           | Hosting  | Confirmed  | 24h     | [Cloudflare IP ranges](https://www.cloudflare.com/ips/)                                       |
| `x4b-datacenter`       | Hosting  | Likely     | 24h     | [X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn) datacenter list                       |
| `hosting-asn`          | Hosting  | Likely     | -       | The bundled [`hosting-asns.txt`](src/main/resources/hosting-asns.txt), matched on the MaxMind ASN |

Lookups are a binary search over merged, sorted ranges (IPv4 and IPv6), so they take microseconds regardless of list
size.

### Keeping the data trustworthy

Bad upstream data is the main cause of false positives, so every refresh goes through a guard before it's used:

- Entries that don't parse are skipped.
- Entries that are too broad (wider than `/8` for IPv4 or `/24` for IPv6) or overlap private/reserved space are
  dropped. If more than 1% of a refresh is like that, the whole refresh is rejected.
- A refresh with fewer than half the entries of the previous one is rejected, as that's almost always an error page or a
  truncated download.
- A rejected or failed refresh keeps the last good data. Each source's last good copy is saved to
  `data/sources/<id>.txt`, so a restart doesn't depend on upstream being reachable.
- A source whose data is older than 3 refresh intervals (and at least 24 hours) is **stale** and ignored for lookups,
  rather than answering with outdated data. `/stats` shows each source's state and last error.

### The verdict

- `vpn` is only true for **VPN** detections, from a provider's own server list (`vpnProvider: true`) or the X4BNet VPN
  list.
- `tor`, `relay`, `hosting` and `abuse` are reported separately. Hosting alone is **not** a VPN. Plenty of legitimate
  traffic (corporate proxies, CI runners, crawlers) comes from datacenters, so decide for yourself whether to block it.
- **iCloud Private Relay** is used by ordinary iPhone and Mac users. Its egress runs on Akamai, Cloudflare and Fastly,
  which are also in hosting lists, so a relay match suppresses hosting and likely-VPN matches. It is reported as
  `relay: true` with a low risk.
- `risk` (0 to 1) is the weight of the strongest signal, plus the operator blacklist weights, capped at 1. Signals
  don't stack: an address that is both on AWS and a hosting ASN is still 0.5.
- Allowlisted addresses are always clean (`risk: 0`, no detections).

| Signal                           | Default weight |
|----------------------------------|----------------|
| VPN (confirmed, provider list)   | 1.0            |
| VPN (likely, third party)        | 0.75           |
| Tor                              | 1.0            |
| Abuse (Spamhaus DROP)            | 0.9            |
| Hosting                          | 0.5            |
| Relay (iCloud Private Relay)     | 0.1            |
| ASN blacklist (added on top)     | 0.5            |
| Country blacklist (added on top) | 0.4            |

A sensible policy for most apps is to block on `vpn || tor`, and treat `hosting` or `risk >= 0.5` as a reason for extra
verification rather than a block.

### Hosting ASNs

[`hosting-asns.txt`](src/main/resources/hosting-asns.txt) is a curated list of networks that only host servers (clouds,
VPS providers, and networks that mostly carry VPN exits, such as M247 and Datacamp). It deliberately **excludes**
networks that also carry consumer traffic, such as Google (15169), Microsoft (8075), Cloudflare (13335, WARP), Akamai,
Fastly and Cogent. Add your own with `detection.extra-hosting-asns`.

## API

Every route except `/amiusingavpn` and `/actuator/health` needs an API key in the `X-API-Key` header (configurable with
`auth.header`). Anonymous requests are limited to 100 per minute per IP.

Set `auth.admin-key` (`ADMIN_API_KEY`) to an API key of at least 16 characters, and it's created on start with every
permission and no rate limits. Changing it revokes the previous admin key. Without it, a random fully privileged key is generated on first
start and logged **once**.

Errors are always JSON:

```json
{ "timestamp": "2026-09-27T12:00:00Z", "status": 400, "error": "Bad Request", "message": "Cannot lookup private or reserved IP ranges", "path": "/check" }
```

| Method   | Route                                        | Permission             | Description                                                     |
|----------|----------------------------------------------|------------------------|-----------------------------------------------------------------|
| `GET`    | `/check?ip=<ip or domain>`                   | -                      | Look up an address                                              |
| `GET`    | `/check?ip=...&data=ASN,GEOGRAPHICAL`        | -                      | Include ASN and/or location data                                |
| `GET`    | `/check?ip=...&ignoreCache=true`             | `IGNORE_ADDRESS_CACHE` | Skip the cache                                                  |
| `GET`    | `/amiusingavpn`                              | none (no key)          | Check the caller's own IP, disabled unless `amiusingavpn: true` |
| `GET`    | `/stats`                                     | `VIEW_STATS`           | Source status, list sizes and memory usage                      |
| `POST`   | `/blacklist/modify?type=ASN\|COUNTRY&entry=` | `MANAGE_BLACKLIST`     | Toggle a blacklist entry (`AS13335`, `GB`, `United Kingdom`)    |
| `GET`    | `/blacklist/list`                            | `MANAGE_BLACKLIST`     | List the blacklists                                             |
| `POST`   | `/allowlist/modify?type=IP_RANGE\|ASN&entry=`| `MANAGE_BLACKLIST`     | Toggle an allowlist entry (`203.0.113.0/24`, `AS1221`)          |
| `GET`    | `/allowlist/list`                            | `MANAGE_BLACKLIST`     | List the allowlists                                             |
| `DELETE` | `/cache/purge`                               | `PURGE_CACHE`          | Clear the lookup cache                                          |
| `GET`    | `/actuator/health`                           | none (no key)          | Health, with `/liveness` and `/readiness` probes                |

Domains are resolved first, and the resolved address is validated like any other input. Private and reserved addresses
(RFC 1918, loopback, CGNAT, link-local, documentation ranges, ULA, multicast and so on) are rejected with `400`.
IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are treated as IPv4.

A lookup with `data=ASN,GEOGRAPHICAL` also includes:

```json
{
  "asn": { "number": 9009, "organization": "M247 Europe SRL", "network": "89.35.28.0/22" },
  "geographical": {
    "continentCode": "EU", "continent": "Europe", "countryIsoCode": "RO", "country": "Romania", "europeanUnion": true,
    "city": "Bucharest", "latitude": 44.4, "longitude": 26.1, "timezone": "Europe/Bucharest"
  }
}
```

Results are cached in Redis for 30 minutes. Cached responses include `"cached": <epoch millis>`. The cache is
invalidated automatically whenever a source refreshes or a list changes, so a cached answer is never computed from
older data than a fresh one would be. If Redis is down, lookups still work, just uncached.

A [Postman collection](postman_collection.json) with every route is included.

## Running it

### Docker Compose

```bash
cp .env.example .env   # set DATABASE_PASSWORD, ADMIN_API_KEY and your MaxMind credentials
docker compose up -d
```

If you left `ADMIN_API_KEY` blank, the generated key is in the logs: `docker compose logs antivpn | grep "Default API key"`.

This starts AntiVPN with MariaDB and Redis. The image is published to `ghcr.io/rainnny7/antivpn` for `linux/amd64` and
`linux/arm64`. Source snapshots and the MaxMind databases are kept in volumes (`/app/data` and `/app/maxmind`).

### MaxMind

ASN and location data come from the free [GeoLite2](https://www.maxmind.com/en/geolite2/signup) databases. Set
`MAXMIND_ACCOUNT_ID` and `MAXMIND_LICENSE` and they're downloaded on start, and re-downloaded when older than 7 days.
Without credentials, AntiVPN uses whatever `GeoLite2-ASN.mmdb` and `GeoLite2-City.mmdb` are already in
`maxmind.directory`. Without an ASN database, hosting-ASN detection and ASN blacklists/allowlists don't work.

### Behind a reverse proxy

Forwarding headers are ignored by default, since anyone can send them. If AntiVPN is behind a proxy, list its addresses
so `X-Forwarded-For` is trusted from it (used for `/amiusingavpn`, anonymous rate limits and request logs):

```yaml
detection:
  trusted-proxies: [ "10.0.0.0/8", "172.16.0.0/12" ]
  trust-cloudflare: true # Honor CF-Connecting-IP, only from Cloudflare's published ranges
```

## Configuration

Everything lives in [`application.yml`](src/main/resources/application.yml). Override it with environment variables
(`DATABASE_URL`, `REDIS_HOST`, `DETECTION_TRUSTCLOUDFLARE=true`, ...) or an `application.yml` in `./config/`
(`/app/config/` in Docker).

| Property                                    | Default          | Description                                                   |
|---------------------------------------------|------------------|---------------------------------------------------------------|
| `spring.datasource.url` / `DATABASE_URL`    | local MariaDB    | Stores API keys, blacklists and allowlists                    |
| `spring.data.redis.host` / `REDIS_HOST`     | `127.0.0.1`      | Lookup cache                                                  |
| `maxmind.account-id`, `maxmind.license`     | empty            | GeoLite2 credentials                                          |
| `maxmind.directory`                         | `maxmind`        | Where the `.mmdb` files are stored                            |
| `influxdb.url`, `token`, `org`, `bucket`    | empty            | Optional metrics (see [`grafana_dashboard.json`](grafana_dashboard.json)) |
| `auth.header`                               | `X-API-Key`      | The API key header                                            |
| `auth.admin-key` / `ADMIN_API_KEY`          | empty            | An API key with every permission and no rate limits           |
| `detection.scheduling-enabled`              | `true`           | Refresh sources on a schedule                                 |
| `detection.snapshot-directory`              | `data/sources`   | Where the last good copy of each source is kept               |
| `detection.disabled-sources`                | `[]`             | Source ids to skip, e.g. `[ "x4b-datacenter", "aws" ]`        |
| `detection.trusted-proxies`                 | `[]`             | CIDR blocks whose `X-Forwarded-For` is trusted                |
| `detection.trust-cloudflare`                | `false`          | Trust `CF-Connecting-IP` from Cloudflare's ranges             |
| `detection.stale-after-multiplier`          | `3`              | Refresh intervals before a source is stale                    |
| `detection.min-stale-after`                 | `24h`            | Minimum age before a source is stale                          |
| `detection.min-retained-ratio`              | `0.5`            | Reject a refresh smaller than this fraction of the last one   |
| `detection.max-unsafe-ratio`                | `0.01`           | Reject a refresh with more unsafe entries than this           |
| `detection.extra-hosting-asns`              | `[]`             | Extra hosting ASNs                                            |
| `detection.weights.*`                       | see above        | Risk weights                                                  |
| `amiusingavpn`                              | `false`          | Enable `/amiusingavpn`                                        |

## Development

Requires Java 21. Docker is optional.

```bash
./mvnw verify            # Unit, web and application tests, plus MariaDB/Redis integration tests when Docker is available
./mvnw test -Plive       # Fetch every source from upstream and check the data is usable
./mvnw spring-boot:run   # Run locally (needs MariaDB, Redis is optional)
```

The tests run against captured upstream responses in [`src/test/resources/fixtures`](src/test/resources/fixtures) and
MaxMind's [test databases](https://github.com/maxmind/MaxMind-DB), so they don't need the network. CI runs the full
suite on every push and pull request, and the live source tests run weekly to catch upstream format changes.

To add a source, extend `DetectionSource` (or `PlainListSource` for one-entry-per-line lists), annotate it with
`@Component`, add a fixture and a parser test, and add it to `LiveSourcesTest`.

### Upgrading from 1.x

Provider addresses are no longer stored in the database. They live in memory with snapshots on disk, so the old table
can be dropped:

```sql
DROP TABLE provider_ips;
```

API keys and blacklists are kept as they are, and allowlists get new tables automatically. Responses now include
`vpnProvider`, `relay`, `hosting`, `abuse`, `allowlisted` and `detections`. `vpn` no longer includes datacenter
matches, which are reported as `hosting`.

## Limitations

- Only free sources are used. Residential proxy networks, most smaller VPN providers and private VPNs on generic
  hosting won't be detected as VPNs. Many of the latter show up as `hosting`.
- Provider lists cover their servers' **entry** addresses. Most providers exit from the same address, but some don't.
- Surfshark only publishes hostnames, so its coverage depends on what DNS returns over the 14-day window.
- Location data from GeoLite2 is approximate.

## Attribution

This product includes GeoLite2 data created by MaxMind, available from [maxmind.com](https://www.maxmind.com), and
subject to the [GeoLite2 EULA](https://www.maxmind.com/en/geolite2/eula). Detection data comes from
[The Spamhaus Project](https://www.spamhaus.org/) (DROP, subject to its [terms](https://www.spamhaus.org/drop/terms/)),
[X4BNet lists_vpn](https://github.com/X4BNet/lists_vpn), [The Tor Project](https://www.torproject.org/), Apple, Amazon
Web Services, Google Cloud, Cloudflare, NordVPN, Private Internet Access, Mullvad and Surfshark. The test databases in
`src/test/resources/maxmind` are from [MaxMind-DB](https://github.com/maxmind/MaxMind-DB).
