// Quick and dirty powerdns exporter. Grabs metrics by the control socket and
// does a port mapping.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/log"
	"net"
	"github.com/julienschmidt/httprouter"
	"bytes"
	"strconv"
	"strings"
	"io"
	"time"
	"sync"
)

const namespace = "pdns"
const subsystem = "exporter"

var (
	Version = "0.0.0.dev"

	listenAddress     = flag.String("web.listen-address", ":34576", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	pdnsControlSocket = flag.String("collector.powerdns.socket", "unix:/var/run/pdns.controlsocket", "Connect string to control socket")
	rateLimitUpdates  = flag.Bool("collector.rate-limit.enable", true, "Limit the number of metric queries to collector.rate-limit.min-cooldown")
	minCooldown		  = flag.Duration("collector.rate-limit.min-cooldown", time.Duration(time.Second * 10), "Minimum cooldown time between metric polls to PowerDNS")
)

var metricDescriptions = map[string]string {
	"corrupt-packets" : "Number of corrupt packets received",
	"deferred-cache-inserts" : "Number of cache inserts that were deferred because of maintenance",
	"deferred-cache-lookup" : "Number of cache lookups that were deferred because of maintenance",
	"dnsupdate-answers" : "Number of DNS update packets successfully answered",
	"dnsupdate-changes" : "Total number of changes to records from DNS update",
	"dnsupdate-queries" : "Number of DNS update packets received",
	"dnsupdate-refused" : "Number of DNS update packets that were refused",
	"incoming-notifications" : "Number of NOTIFY packets that were received",
	"key-cache-size" : "Number of entries in the key cache",
	"latency" : "Average number of microseconds a packet spends within PDNS",
	"meta-cache-size" : "Number of entries in the metadata cache",
	"packetcache-hit" : "Number of packets which were answered out of the cache",
	"packetcache-miss" : "Number of times a packet could not be answered out of the cache",
	"packetcache-size" : "Amount of packets in the packetcache",
	"qsize-q" : "Number of packets waiting for database attention",
	"query-cache-hit" : "Number of hits on the query cache",
	"query-cache-miss" : "Number of misses on the query cache",
	"rd-queries" : "Number of packets sent by clients requesting recursion (regardless of if we'll be providing them with recursion).",
	"recursing-answers" : "Number of packets we supplied an answer to after recursive processing",
	"recursing-questions" : "Number of packets we performed recursive processing for",
	"recursion-unanswered" : "Number of packets we sent to our recursor, but did not get a timely answer for. Since 3.4.0.",
	"security-status" : "Security status based on security polling",
	"servfail-packets" : "Amount of packets that could not be answered due to database problems",
	"signature-cache-size" : "Number of entries in the signature cache",
	"signatures" : "Number of DNSSEC signatures created",
	"sys-msec" : "Number of CPU miliseconds sent in system time",
	"tcp-answers-bytes" : "Total number of answer bytes sent over TCP (since 4.0.0)",
	"tcp-answers" : "Number of answers sent out over TCP",
	"tcp-queries" : "Number of questions received over TCP",
	"tcp4-answers-bytes" : "Total number of answer bytes sent over TCPv4 (since 4.0.0)",
	"tcp4-answers" : "Number of answers sent out over TCPv4",
	"tcp4-queries" : "Number of questions received over TCPv4",
	"tcp6-answers-bytes" : "Total number of answer bytes sent over TCPv6 (since 4.0.0)",
	"tcp6-answers" : "Number of answers sent out over TCPv6",
	"tcp6-queries" : "Number of questions received over TCPv6",
	"timedout-questions" : "Amount of packets that were dropped because they had to wait too long internally",
	"udp-answers-bytes" : "Total number of answer bytes sent over UDP",
	"udp-answers" : "Number of answers sent out over UDP",
	"udp-do-queries" : "Number of queries received with the DO (DNSSEC OK) bit set",
	"udp-in-errors" : "Number of packets, received faster than the OS could process them",
	"udp-noport-errors" : "Number of UDP packets where an ICMP response was received that the remote port was not listening",
	"udp-queries" : "Number of questions received over UDP",
	"udp-recvbuf-errors" : "Number of errors caused in the UDP receive buffer",
	"udp-sndbuf-errors" : "Number of errors caused in the UDP send buffer",
	"udp4-answers-bytes" : "Total number of answer bytes sent over UDPv4 (Since 4.0.0)",
	"udp4-answers" : "Number of answers sent out over UDPv4",
	"udp4-queries" : "Number of questions received over UDPv4",
	"udp6-answers-bytes" : "Total number of answer bytes sent over UDPv6 (Since 4.0.0)",
	"udp6-answers" : "Number of answers sent out over UDPv6",
	"udp6-queries" : "Number of questions received over UDPv6",
	"uptime" : "Uptime in seconds of the daemon",
	"user-msec" : "Number of milliseconds spend in CPU 'user' time",
}

func NewExporter(pdnsControlSocket string, rateLimiterEnabled bool, rateLimiterCooldown time.Duration) *Exporter {
	splitAddr := strings.Split(pdnsControlSocket, ":")
	proto := splitAddr[0]
	addr := splitAddr[1]

	return &Exporter{
		proto,
		addr,
		prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name: "last_scrape_error",
			Help: "1 if the last scrape failed for any reason",
		}),
		rateLimiterEnabled,
		rateLimiterCooldown,
		time.Time{},
		make(map[string]float64),
		sync.RWMutex{},
	}
}

type Exporter struct {
	// Connect config
	controlProto string
	controlAddr  string

	// Informational metrics
	error prometheus.Gauge

	// Rate limiter confit
	rateLimiterEnabled bool
	rateLimiterCooldown time.Duration

	lastPoll time.Time	// Time of last poll

	metricCache map[string]float64	// Metric cache
	mtx sync.RWMutex
}

// Describe implements prometheus.Collector.
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// We cannot know in advance what metrics the exporter will generate
	// from Postgres. So we use the poor man's describe method: Run a collect
	// and send the descriptors of all the collected metrics.

	metricCh := make(chan prometheus.Metric)
	doneCh := make(chan struct{})

	go func() {
		for m := range metricCh {
			ch <- m.Desc()
		}
		close(doneCh)
	}()

	e.Collect(metricCh)
	close(metricCh)
	<-doneCh
}

// Collect implements prometheus.Collector.
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	// Try and scrape (may return immediately due to cache limiting)
	e.scrape(ch)

	e.mtx.RLock()
	defer e.mtx.RUnlock()

	// Emit metrics
	for key, value := range e.metricCache {
		var help string
		help, ok := metricDescriptions[key]
		if !ok {
			help = fmt.Sprintf("unknown metric: %s", help)
		}
		desc := prometheus.NewDesc(key, help, nil, nil)
		ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, value)
	}

	e.error.Collect(ch)
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) {
	// Check if poll allowed
	if (e.lastPoll.Sub(time.Now()) < e.rateLimiterCooldown) && e.rateLimiterEnabled {
		log.Debugln("Rate-limiting request - cached data will be used.")
		return
	}
	log.Debugln("Cooldown expired, getting new data")
	e.lastPoll = time.Now()

	e.error.Set(0)

	// Connect and get metrics
	conn, err := net.Dial(e.controlProto, e.controlAddr)
	if err != nil {
		log.Errorln("connect:",err)
		e.error.Set(1)
		return
	}
	defer conn.Close()

	_, err = conn.Write([]byte("SHOW *\n"))
	if err != nil {
		log.Errorln("write:",err)
		e.error.Set(1)
		return
	}

	var buf bytes.Buffer
	n, err := io.Copy(&buf, conn)
	if err != io.EOF && err != nil {
		log.Errorln("read:", err)
		e.error.Set(1)
		return
	}

	log.Debugln("Read ", n, "bytes from control port")

	metricStrings := strings.Split(buf.String(), ",")
	// Update the internal map
	e.mtx.Lock()
	defer e.mtx.Unlock()
	for _, rawMetric := range metricStrings {
		// Last metric always produces a blank value
		if len(rawMetric) == 0 {
			continue
		}

		// Split into keys and values
		vals := strings.Split(rawMetric, "=")
		if len(vals) != 2 {
			log.Errorln("process: did not get a pair of values")
			e.error.Set(1)
			return
		}

		key := vals[0]	// Metric name
		value := vals[1]	// Metric value

		// Post-process name to prometheus style
		prometheusKey := strings.Replace(key, "-", "_", -1)

		// Post process value to prometheus format
		prometheusValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.Errorln(err)
			e.error.Set(1)
			return
		}

		e.metricCache[prometheusKey] = prometheusValue
	}
}

func main() {
	flag.Parse()

	ex := NewExporter(*pdnsControlSocket, *rateLimitUpdates, *minCooldown)
	prometheus.MustRegister(ex)

	router := httprouter.New()
	router.Handler("GET", "/metrics", prometheus.Handler())

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		defer r.Body.Close()
		w.Write([]byte(`<html>
			<head><title>PowerDNS quick exporter</title></head>
			<body>
			<h1>PowerDNS quick exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infof("Starting pdns_exporter v%s at %s", Version, *listenAddress)
	err := http.ListenAndServe(*listenAddress, router)
	if err != nil {
		log.Fatal(err)
	}
}