# caddy-netacl

A Caddy v2 module that allows or denies requests by **IP/CIDR, ASN, country
and continent**. It uses **named groups** and an **ordered, first-match-wins
rule list**, so a policy reads like a firewall ruleset.

It reads the free [DB-IP Lite](https://db-ip.com/db/lite.php) MMDB files
directly, and can download and update them itself. MaxMind GeoLite2 files with
the same layout work too. There is no account, API key, cron job or second
plugin to set up.

```caddyfile
{
	netacl {
		auto_update

		group office   203.0.113.0/24 198.51.100.7
		group vpn      10.8.0.0/16
		group staff    @office @vpn
		group badhosts asn 12345 67890
		group friendly country DE SE NO
		group blocklist ip_file /etc/netacl/blocklist.txt
	}
}

example.com {
	netacl {
		allow @staff
		deny  @badhosts @blocklist
		allow @friendly
		allow ip 192.0.2.10
		default deny
	}
	reverse_proxy localhost:8080
}
```

## Install

```sh
xcaddy build --with github.com/tbshfr/caddy-netacl
```

Requires Go 1.26 or newer, the same as Caddy itself.

Add `auto_update` to the global `netacl` options and Caddy fetches the
databases itself (see [Databases](#databases)).

## Configuration

### Global options

Databases and groups are defined once, in the global options block, and can be
used from any site. Every option is optional, and an IP-only setup needs no
global block at all.

```caddyfile
{
	netacl {
		auto_update                  # download and update DB-IP Lite
		db_country      <path>       # your own country (or city) MMDB
		db_asn          <path>       # your own ASN MMDB
		reload_interval <duration>   # re-read changed files; default off, minimum 1s
		group <name> <selectors...>
		group <name> <selectors...> {
			<selectors...>
			...
		}
	}
}
```

Where the databases come from:

| You set | Country database | ASN database |
|---|---|---|
| `auto_update` only | DB-IP, managed for you | DB-IP, managed for you |
| `auto_update` and `db_asn` | DB-IP, managed for you | your file |
| `db_country` and/or `db_asn`, no `auto_update` | your file | your file |
| nothing | country and continent rules are a config error | ASN rules are a config error |

With `auto_update`, `db_country` and `db_asn` are not needed. Set one only
to use your own file for that database instead of DB-IP.

- **Groups** can include other groups (`@name`), can mix selector types, and
  are resolved when the config loads. Unknown names, cycles (`a -> b -> a`)
  and duplicate names are config errors.
- Inside a group, a bare IP or CIDR works without the `ip` keyword.
- A long group can continue in a block. Each line in the block is more
  members of the same group.
- A database file is opened only if a rule that is actually used needs it. An
  IP-only configuration never touches `db_country` or `db_asn`.
- Paths may use Caddy placeholders such as `{env.NETACL_DIR}`.

### The `netacl` directive

```caddyfile
netacl {
	allow           <selectors...>
	deny            <selectors...>
	default         allow|deny
	status          <code>       # optional; default 403
	on_lookup_error skip|deny    # optional; default skip
}
```

A denied request ends with a Caddy HTTP error, so you can style the response
with `handle_errors`:

```caddyfile
handle_errors {
	respond "Access denied ({err.status_code})" {err.status_code}
}
```

The directive is ordered **before every standard directive** (ahead of
`tracing`), so it also runs ahead of plugins that order themselves relative to
a standard directive, such as `static_redirects`. Nothing else in the same
site can answer before the policy is checked.

A global `order X first` still puts `X` ahead of netacl. To keep netacl first
alongside such plugins, order them after it, for example with
[caddy-crowdsec-bouncer](https://github.com/hslatman/caddy-crowdsec-bouncer):

```caddyfile
{
	order netacl first
	order crowdsec after netacl
	order appsec after crowdsec
}
```

If you need a different position, wrap it in `route`:

```caddyfile
route {
	rewrite /old /new
	netacl { ... }
	reverse_proxy localhost:8080
}
```

### The `netacl` matcher

The matcher names the decision it matches, so its polarity is always explicit:

```caddyfile
@blocked netacl deny {
	deny @badhosts
	deny country UNK
	default allow
}
respond @blocked "Forbidden" 403
```

`netacl allow { ... }` matches when the decision is allow. The decision
keyword is required. `status` is not accepted in the matcher;
`on_lookup_error` is.

### Rule grammar

```
rule     := (allow | deny) selector...
default  := default (allow | deny)         # required, exactly once, last
selector := @group
          | ip <ip-or-cidr>...
          | ip_file <path>...
          | private_ranges
          | asn <number>...
          | country <ISO 3166-1 alpha-2 | UNK>...
          | continent <AF|AN|AS|EU|NA|OC|SA>...
```

- Selectors in one rule are OR'd, and so are group members. Repeat a keyword
  to switch back to it: `allow ip 192.0.2.1 asn 64496 ip 198.51.100.0/24`.
- `asn` accepts `64496` or `AS64496`. ASN 0 is reserved and rejected.
- Country and continent codes are case-insensitive.
- `private_ranges` uses Caddy's own list, the same as `remote_ip private_ranges`.
- `ip_file` reads one IP or CIDR per line. Blank lines and text after `#` are
  ignored. An invalid line is a config error that names the file and line
  number.

## Semantics

Rules run top to bottom. The first rule with a matching selector decides. If
no rule matches, `default` decides.

| Situation | Behaviour |
|---|---|
| Several rules match | The first one in file order wins. Later rules are not evaluated. |
| Private, loopback, link-local or unspecified address | Never looked up. Only `ip`, `ip_file` and `private_ranges` can match. `country UNK` does **not** match. |
| Address not in the country database | `country`/`continent` selectors do not match, except `country UNK`. |
| Address has a continent but no country in the database | `continent` can match. `country UNK` matches. |
| Address not in the ASN database | `asn` selectors do not match. |
| IPv4-mapped IPv6 (`::ffff:a.b.c.d`) | Unmapped to IPv4 before matching, for both client addresses and configured prefixes. |
| No client IP available | Treated as an unknown address, so `default` decides. Logged at debug level. |
| Database lookup fails | Depends on `on_lookup_error`, see [Lookup errors](#lookup-errors). |
| A rule can never match | A warning at config load, e.g. `allow @staff` after `allow private_ranges` when staff is all private. |

Addresses that are public but absent from the database, such as CGNAT
`100.64.0.0/10`, count as `UNK`. Exempt them with an `ip` rule if you deny
`UNK`.

Each request looks up each database at most once: the first selector that
needs a country or ASN fetches it. The result is shared with the remaining
rules, the request vars, and any other `netacl` handler or matcher on the same
request.

### Lookup errors

Databases are verified when they load, so a lookup that fails at request time
is rare. If one does fail, `on_lookup_error` decides what happens:

- `skip` (default): the selectors that needed the lookup do not match, and
  evaluation continues with the next selector and rule. This **fails open**
  for deny rules. With `deny country CN` and `default allow`, a failed lookup
  lets the request through.
- `deny`: the request is denied as soon as a rule cannot be checked. This
  **fails closed**. `netacl_rule` is set to `lookup_error`, and the handler
  responds with its `status`.

Either way, the failure is counted in
`caddy_netacl_lookups_total{result="error"}`. It is also logged at `error`,
at most once a minute, so a broken database cannot flood the logs. Rules that
decide before a lookup is needed, such as an `ip` rule that matches, and
private addresses, which are never looked up, are not affected.

```caddyfile
netacl {
	deny country CN RU
	on_lookup_error deny
	default allow
}
```

### Client IP

netacl uses Caddy's `client_ip`, which applies the server's `trusted_proxies`
and `client_ip_headers` settings. It never reads `X-Forwarded-For` or other
headers itself, so it cannot be spoofed past Caddy's proxy trust settings.
Behind a proxy, CDN or tunnel, configure trust in the global options:

```caddyfile
{
	servers {
		trusted_proxies static private_ranges
	}
}
```

## Databases

| Slot | Accepts |
|---|---|
| `db_country` | DB-IP Country Lite, DB-IP City Lite, GeoLite2/GeoIP2 Country or City |
| `db_asn` | DB-IP ASN Lite, GeoLite2 ASN |

The database type in the file's metadata is checked at load time. An ASN file
in the country slot, or the reverse, is a config error.

Each file is read fully into memory and verified before it is used. It is
never memory-mapped. A file that is truncated or rewritten while Caddy is
running therefore cannot crash Caddy, and a swap never affects requests in
flight.

### Automatic download and updates

With `auto_update`, netacl manages DB-IP Lite for you:

- The files live in Caddy's data directory, next to its certificates, under
  `netacl/` (for example `~/.local/share/caddy/netacl/` or
  `/var/lib/caddy/.local/share/caddy/netacl/` for the packaged service). The
  directory is created automatically. `XDG_DATA_HOME` moves it, as it does for
  Caddy itself.
- A database is only downloaded when a rule needs it. An IP-only config
  downloads nothing.
- If a needed file is missing, or the stored file is unusable (for example
  truncated by a full disk), it is downloaded while the config loads
  (`caddy run`, `caddy reload`, and also `caddy validate`, which therefore
  writes to the data directory). Later starts reuse the stored file.
- Caddy needs outbound HTTPS access to `download.db-ip.com`.
- When the config loads, and every 6 hours after that, netacl checks whether
  the loaded release is older than the current month. If so, it fetches the
  new release once DB-IP has published it, usually a few hours into the month.
  Until then the server answers 404, and netacl keeps the current file.
- Downloads are verified like any database load before they replace the stored
  file with an atomic rename. The new data is swapped into the running server
  directly, so `reload_interval` is **not** needed for managed databases. A
  failed or invalid download is logged, counted in
  `caddy_netacl_db_downloads_total{result="error"}`, and changes nothing.

`auto_update` only manages the databases you don't set yourself. For example,
with `auto_update` and `db_asn /path/GeoLite2-ASN.mmdb`, the country database
comes from DB-IP and the ASN database from your file.

> **First start without network.** If a needed database has never been
> downloaded and DB-IP cannot be reached, the config fails to load, which
> stops all sites, not only the ones using netacl. After the first successful
> download, an outage only delays updates. To avoid that dependency on a new
> host, copy the files into the data directory beforehand, or set `db_country`
> and `db_asn` to files you provide.

### Using your own files

Set `db_country` and `db_asn` to files you maintain, for example GeoLite2
databases kept current by MaxMind's `geoipupdate`. Replace them with an atomic
rename (write to a temporary file in the same directory, then `mv`). Combine
this with `reload_interval` to pick up changes without a `caddy reload`.

### Reloading

With `reload_interval` set, netacl checks the databases and every `ip_file`
on that interval. When a file's size, modification time or inode changes, it
loads the new version, validates it and swaps it in. If the new file is
invalid, the error is logged, `caddy_netacl_db_reloads_total{result="error"}`
is incremented, and the previous data keeps serving. The bad version is not
retried until the file changes again.

Without `reload_interval`, changes take effect on `caddy reload`.

| File | Needs `reload_interval` to pick up changes? |
|---|---|
| Database managed by `auto_update` | No, downloads are swapped in directly |
| Your own `db_country` / `db_asn`, even alongside `auto_update` | Yes |
| `ip_file` | Yes |

For a frequently updated `ip_file` blocklist, use a short interval such as
`1m`. The minimum is `1s`. Checking costs one `stat` per file per interval.

## Observability

### Request vars

Every evaluation sets these vars, which you can add to access logs with
`log_append`:

| Var | Example | Notes |
|---|---|---|
| `netacl_decision` | `deny` | `allow` or `deny` |
| `netacl_rule` | `2` | Zero-based index of the matching rule, `default`, or `lookup_error` |
| `netacl_country` | `DE` | Empty if not looked up. `UNK` if not found. |
| `netacl_continent` | `EU` | Empty if not looked up or not found |
| `netacl_asn` | `3320` | Empty if not looked up or not found |

```caddyfile
log_append netacl_decision {vars.netacl_decision}
log_append netacl_rule     {vars.netacl_rule}
log_append netacl_country  {vars.netacl_country}
```

Lookups are lazy. When an earlier rule decides, a later database may never be
queried, and its var stays empty.

### Logs

Each time a config loads, netacl logs `started` at `info`. The line lists
the database files in use (`unused` for one no rule needs), the number of
`ip_file` lists and groups, and whether `auto_update` and `reload_interval`
are on. Database downloads, loads and reloads, and `ip_file` loads and reloads, are
logged at `info`. Failures are logged at `error`. Per-request decisions and
lookups are logged at `debug` only, so client IPs do not appear in normal
logs.

### Metrics

With `metrics` enabled in Caddy:

| Metric | Labels |
|---|---|
| `caddy_netacl_decisions_total` | `decision` |
| `caddy_netacl_lookups_total` | `db` (`country`, `asn`), `result` (`hit`, `miss`, `error`) |
| `caddy_netacl_db_reloads_total` | `db` (`country`, `asn`, `ip_file`), `result` (`success`, `error`) |
| `caddy_netacl_db_downloads_total` | `db` (`country`, `asn`), `result` (`success`, `error`) |
| `caddy_netacl_db_build_epoch_seconds` | `db`: alert on this to catch stale databases |

## JSON config

```json
{
  "apps": {
    "netacl": {
      "auto_update": true,
      "groups": {
        "office":   { "ips": ["203.0.113.0/24"] },
        "staff":    { "groups": ["office"], "private_ranges": true },
        "friendly": { "countries": ["DE", "SE"], "continents": ["OC"] }
      }
    },
    "http": { "servers": { "srv0": { "routes": [{ "handle": [{
      "handler": "netacl",
      "rules": [
        { "action": "allow", "groups": ["staff"] },
        { "action": "deny",  "asns": [12345], "ip_files": ["/etc/netacl/block.txt"] },
        { "action": "allow", "groups": ["friendly"] }
      ],
      "default": "deny",
      "status_code": 403,
      "on_lookup_error": "skip"
    }]}]}}}
  }
}
```

The matcher is `{"netacl": {"decision": "deny", "rules": [...], "default": "allow"}}`.

## Errors at config load

Syntax errors are reported by `caddy adapt` with the file and line: invalid
IP/CIDR, ASN (including ASN 0), country or continent; a missing, repeated or
misplaced `default`; a matcher without its decision; an invalid or repeated
`on_lookup_error` or `reload_interval`, or an interval below `1s`; duplicate
group names; unknown group references and cycles inside the global block.

The following are checked when modules are provisioned (`caddy validate`,
`caddy run`, `caddy reload`):

- unreadable `ip_file`s and invalid lines in them
- a rule referencing an unknown group
- a rule that needs a database that is not configured, cannot be read, or is
  of the wrong type
- with `auto_update`, a needed database that is not stored yet (or is
  unusable) and cannot be downloaded

## Data licence and attribution

netacl ships no geolocation data. Either you download it, or `auto_update`
downloads it on your behalf. Either way, the data's licence applies to your
deployment.

DB-IP Lite databases are licensed under
[Creative Commons Attribution 4.0](https://creativecommons.org/licenses/by/4.0/).
DB-IP asks that pages which display or use results from the database link
back to DB-IP, for example:

```html
<a href='https://db-ip.com'>IP Geolocation by DB-IP</a>
```

See <https://db-ip.com/db/lite.php> for the current terms. GeoLite2 data has
its own licence and requires a MaxMind account.

## Development

```sh
go test -race ./...                       # all tests
go test -run TestCaddyfileAdapt -update   # accept new adapt golden output
go test -run XXX -bench .                 # evaluation cost with 10, 1k and 100k prefixes
```

The tests run against the real DB-IP Lite databases. On first use they are
downloaded into `testdata/dbip/` (git-ignored) and reused afterwards. Delete
`testdata/dbip/*.mmdb` to fetch the current month again. The rule-engine,
group and Caddyfile tests need no network access.

## Licence

MIT, see [LICENSE](LICENSE).
