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
  Default `authoritative:unix:/var/run/powerdns.controlsocket`. 
  Comma separed list of paths to PowerDNS instances to monitor.
  Must be prefixed with the type of server being monitored, either
  `authoritative` or `recursor`.
  
* `collector.powerdns.local-socket.mode`
  Default `640`. Modifies permissions on the local socket used to receive
  responses from the recursor

* `collector.tempdir.prefix`
  Default is blank. If specified modifies the prefix used for where response
  sockets are created for talking to a recursor with unixgrams. This should be
  set if you are trying to monitor with `pdns_exporter` in a Docker container,
  and should be set to a shared volume between the exporter container and the
  `pdns_recursor` container.

* `collector.rate-limit.enable`
  Default `true`. If enabled, metrics will be cached and only re-collected whenadter `collector.rate-limit.min-cooldown`
  seconds.

* `collector.rate-limit.min-cooldown`
  Default `10s`. Minimum time between allowing scrapes of the server.

* `collector.timeout`
  Default `1s`. Maximum time to wait for a PowerDNS control socket to respond.

# Monitoring pdns_recursor

`pdns_recursor` uses a `unixgram` rather then `unix` control socket. To monitor
a `pdns_recursor` process use the following settings:
```bash
$ ./pdns_exporter.x86_64 -collector.powerdns.socket=recursor:unixgram:/run/pdns_recursor.controlsocket
```
The process also needs to run as the same user as pdns itself, otherwise control
socket replies won't work. The `-collector.powerdns.local-socket.mode` option
can help in this regard by altering the permissions on the launched process to
be looser. The default is `640`.