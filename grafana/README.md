# Grafana dashboard

[`caddy-netacl.json`](caddy-netacl.json) is a Grafana dashboard for the
[netacl metrics](../README.md#metrics). It needs a Prometheus data source
(or one that speaks PromQL, such as Thanos, Mimir or VictoriaMetrics) that
scrapes Caddy with `metrics` enabled.

## Import

In Grafana, go to Dashboards -> New -> Import, upload `caddy-netacl.json` and
pick your Prometheus data source.

Then set **Scrape interval** in the data source settings (Connections -> Data
sources -> your Prometheus) to the interval Prometheus actually scrapes Caddy
with. The rate panels use `$__rate_interval`, which is derived from that
setting. Grafana assumes 15s if it is unset, which makes graphs coarser than
necessary for faster scrapes and leaves gaps for slower ones.

## Panels

| Row | Shows |
|---|---|
| Decisions | Evaluations per second, deny ratio and allow/deny totals over the selected range; decisions over time; deny ratio per instance |
| Database lookups | Lookups per second by database and result, hit ratio, lookup errors |
| Databases | Age and build date of the loaded databases, reload and download errors, reloads and `auto_update` downloads over time |

The `job` and `instance` variables filter every panel.

Totals and ratios in the stat panels cover the selected time range. Graphs
show per-second rates, so at low traffic most points are small fractions,
and the deny ratio graph has gaps wherever a window saw no requests.

Database age turns orange after 35 days and red after 45, which suits the
monthly DB-IP Lite release that `auto_update` fetches. If you load GeoLite2
files yourself (updated twice a week), lower the thresholds in the panel.
