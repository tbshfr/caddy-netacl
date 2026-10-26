# Lists

Address ranges of third-party services, for the `list` selector of
[caddy-netacl](../README.md#lists). The
[`Update IP lists`](../.github/workflows/update-lists.yml) workflow
regenerates them from each service's own source every week and commits any
change. Do not edit the files by hand.

| List | Contents | Source |
|---|---|---|
| `github/hooks` | Webhook deliveries from GitHub | [`api.github.com/meta`](https://api.github.com/meta), `hooks` |
| `github/actions` | GitHub-hosted Actions runners (about 7000 ranges) | [`api.github.com/meta`](https://api.github.com/meta), `actions` |

## How caddy-netacl uses them

- Lists are opt-in. A list is only downloaded if a rule that is actually used
  needs it, so a config without `list` selectors makes no requests. A list
  that only appears in an unused group is not downloaded either.
- `list <name>` fetches `<lists_url>/<name>.txt`. The default `lists_url` is
  `https://raw.githubusercontent.com/tbshfr/caddy-netacl/main/lists`, so
  Caddy needs outbound HTTPS access to `raw.githubusercontent.com`.
- Lists are cached in Caddy's data directory under `netacl/lists/`. Later
  starts and `caddy reload` use the cache. Each `lists_url` gets its own
  cache directory, so changing it never reuses lists cached from another
  source.
- Each list is checked for changes once a day, with a conditional request
  when the server sends an `ETag`. A new version is swapped into the running
  server directly, so `reload_interval` is not needed.
- If a needed list has never been downloaded and cannot be fetched, the
  config fails to load, the same as a database (see
  [First start without network](../README.md#automatic-download-and-updates)).
  A failed update is logged, counted in
  `caddy_netacl_db_downloads_total{db="list",result="error"}`, retried an hour
  later, and the cached copy keeps serving. `result="success"` counts new
  versions installed, not checks that found the list unchanged.

## Format

The same as an `ip_file`: one IP or CIDR per line, IPv4 and IPv6 mixed, with
blank lines and text after `#` ignored. caddy-netacl additionally rejects a
list that is empty, contains a `/0` prefix or is larger than 16 MB, and keeps
using the previous copy.

List names are their path below the base URL without `.txt`, for example
`github/hooks`. They may use lowercase letters, digits, `_`, `-` and `.`,
with `/` between parts.

## Hosting your own lists

Any static file server or Git hosting served over HTTPS works as a
`lists_url`; plain `http` URLs are rejected. The simplest
way is to fork this repository: the `Update IP lists` workflow regenerates
`lists/` in your fork too. The workflow commits to the default branch, so
that branch must allow pushes from `github-actions[bot]`.

Then point caddy-netacl at your fork:

```caddyfile
{
	netacl {
		lists_url https://raw.githubusercontent.com/you/caddy-netacl/main/lists
	}
}
```

You can also put any other files in the format above under your base URL.

## Adding a service

Add a function to [`update-lists.sh`](../.github/scripts/update-lists.sh)
that fetches the service's source and calls `write_list` for each list, then
run the script. `go test -run TestPublishedLists .` checks the result the
same way caddy-netacl checks a download.
