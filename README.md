[![Build Status](https://travis-ci.org/wrouesnel/pdns_exporter.svg?branch=master)](https://travis-ci.org/wrouesnel/pdns_exporter)
[![Coverage Status](https://coveralls.io/repos/github/wrouesnel/pdns_exporter/badge.svg?branch=master)](https://coveralls.io/github/wrouesnel/pdns_exporter?branch=master)
[![Go Report Card](https://goreportcard.com/badge/github.com/wrouesnel/pdns_exporter)](https://goreportcard.com/report/github.com/wrouesnel/pdns_exporter)

# PowerDNS Prometheus Exporter

An alternate spin on a PowerDNS exporter which works using metrics read from the PowerDNS control-socket, rather than
the REST API. This makes it compatible with older versions of PowerDNS, and avoids the need to turn on or secure the
REST API if it is not needed.

Since older versions of powerDNS blocked the serving loop while metrics are being read, rate-limiting functionality
is included and turned ON by default - that is, multiple prometheus scrapes will be limited by a cool-down period
(by default 10 seconds).

If you are using a newer version (PowerDNS 4+) then this problem does not apply as metric scrapes are atomic, and you
can disable it for more precise metrics.

## CLI Options
* `web.listen-address`
  Default `:9120`

* `web.telemetry-path`
  Default `/metrics`. Web path to expose Prometheus metrics at.

* `collector.powerdns.socket`
  Default `unix:/var/run/powerdns.controlsocket`. Path to the powerdns control socket to collect metrics from.

* `collector.rate-limit.enable`
  Default `true`. If enabled, metrics will be cached and only re-collected whenadter `collector.rate-limit.min-cooldown`
  seconds.

* `collector.rate-limit.min-cooldown`
  Default `10s`. Minimum time between allowing scrapes of the server.

