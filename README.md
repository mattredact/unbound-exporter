# Unbound Exporter

Prometheus exporter for Unbound DNS statistics. Connects via Unix socket and exports metrics for monitoring DNS performance.

Inspired by [ar51an/unbound-exporter](https://github.com/ar51an/unbound-exporter), rewritten with simpler architecture (Unix socket only, no TLS).

## Requirements

- Go 1.19+
- Unbound with control socket enabled

## Unbound Configuration

Enable the control socket in `/etc/unbound/unbound.conf`:

```
remote-control:
    control-enable: yes
    control-interface: /run/unbound.ctl
```

Restart Unbound and verify the socket exists:

```bash
sudo systemctl restart unbound
ls -la /run/unbound.ctl
```

The exporter user needs read access to the socket. Either run as the `unbound` user (recommended) or add your user to the `unbound` group.

## Build

```bash
go mod tidy
go build -o unbound-exporter exporter.go
```

## Usage

```bash
./unbound-exporter --socket-path=/run/unbound.ctl --listen-address=0.0.0.0:9167
```

Options:
```
-l, --listen-address   Address to listen on (default "0.0.0.0:9167")
-m, --metrics-path     Path to expose metrics (default "/metrics")
-s, --socket-path      Path to Unbound control socket (default "/run/unbound.ctl")
    --log-level        Log level: debug, info, warn, error (default "info")
-t, --timeout          Timeout for Unbound queries (default 5s)
```

## Install as Service

```bash
sudo cp unbound-exporter /usr/local/bin/
sudo cp unbound-exporter.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now unbound-exporter
```

## Prometheus Config

```yaml
scrape_configs:
  - job_name: unbound
    static_configs:
      - targets: ['localhost:9167']
```

## Grafana Dashboard

Import `dashboard.json` into Grafana. Uses `${DS_PROMETHEUS}` variable for datasource.

## Metrics

- `unbound_queries_total` - Total DNS queries
- `unbound_cache_hit_total` - Cache hits
- `unbound_cache_miss_total` - Cache misses
- `unbound_recursion_time_avg_seconds` - Average recursion time
- `unbound_memory_caches_bytes{cache}` - Memory by cache type
- `unbound_query_types_count{type}` - Queries by record type (A, AAAA, etc.)
- `unbound_answer_rcodes_count{rcode}` - Responses by code (NOERROR, NXDOMAIN, etc.)
- `unbound_response_time_buckets{lower,upper}` - Response time distribution
- `unbound_time_up_seconds{uptime}` - Server uptime

## License

MIT
