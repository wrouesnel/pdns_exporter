// Quick and dirty powerdns exporter. Grabs metrics by the control socket and
// does a port mapping.

package main

import (
	"flag"
	"fmt"
	"net/http"
	_ "net/http/pprof"

	"bytes"
	"github.com/julienschmidt/httprouter"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/log"
	"io"
	"io/ioutil"
	"net"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

const namespace = "powerdns"
const subsystem = "exporter"

const netUnixgram = "unixgram"

const (
	exportAuthoritative string = "authoritative"
	exportRecursor      string = "recursor"
)

var (
	// Version is populated during build.
	Version = "0.0.0.dev"

	printVersion  = flag.Bool("version", false, "Print version and exit.")
	listenAddress = flag.String("web.listen-address", ":9120", "Address on which to expose metrics and web interface.")
	metricsPath   = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	pdnsControlSocket = flag.String("collector.powerdns.socket", "authoritative:unix:/var/run/pdns.controlsocket", "Connect string to control socket. Can be a comma separated list.")
	localSocketMode   = flag.Uint("collector.powerdns.local-socket.mode", 0640, "Mode to set on the local unixgram reply socket if using unixgrams.")

	tmpDirPrefix = flag.String("collector.tempdir.prefix", "", "Specify directory prefix for temporry sockets. Must be a path pdns_recursor can find if using a dockerized exporter.")

	rateLimitUpdates  = flag.Bool("collector.rate-limit.enable", true, "Limit the number of metric queries to collector.rate-limit.min-cooldown")
	minCooldown       = flag.Duration("collector.rate-limit.min-cooldown", time.Second*10, "Minimum cooldown time between metric polls to PowerDNS")
	collectionTimeout = flag.Duration("collector.timeout", time.Second*1, "Timeout before giving up on scraping PowerDNS socket")
)

var authMetricDescriptions = map[string]string{
	"corrupt-packets":        "Number of corrupt packets received",
	"deferred-cache-inserts": "Number of cache inserts that were deferred because of maintenance",
	"deferred-cache-lookup":  "Number of cache lookups that were deferred because of maintenance",
	"dnsupdate-answers":      "Number of DNS update packets successfully answered",
	"dnsupdate-changes":      "Total number of changes to records from DNS update",
	"dnsupdate-queries":      "Number of DNS update packets received",
	"dnsupdate-refused":      "Number of DNS update packets that were refused",
	"incoming-notifications": "Number of NOTIFY packets that were received",
	"key-cache-size":         "Number of entries in the key cache",
	"latency":                "Average number of microseconds a packet spends within PDNS",
	"meta-cache-size":        "Number of entries in the metadata cache",
	"packetcache-hit":        "Number of packets which were answered out of the cache",
	"packetcache-miss":       "Number of times a packet could not be answered out of the cache",
	"packetcache-size":       "Amount of packets in the packetcache",
	"qsize-q":                "Number of packets waiting for database attention",
	"query-cache-hit":        "Number of hits on the query cache",
	"query-cache-miss":       "Number of misses on the query cache",
	"rd-queries":             "Number of packets sent by clients requesting recursion (regardless of if we'll be providing them with recursion).",
	"recursing-answers":      "Number of packets we supplied an answer to after recursive processing",
	"recursing-questions":    "Number of packets we performed recursive processing for",
	"recursion-unanswered":   "Number of packets we sent to our recursor, but did not get a timely answer for. Since 3.4.0.",
	"security-status":        "Security status based on security polling",
	"servfail-packets":       "Amount of packets that could not be answered due to database problems",
	"signature-cache-size":   "Number of entries in the signature cache",
	"signatures":             "Number of DNSSEC signatures created",
	"sys-msec":               "Number of CPU miliseconds sent in system time",
	"tcp-answers-bytes":      "Total number of answer bytes sent over TCP (since 4.0.0)",
	"tcp-answers":            "Number of answers sent out over TCP",
	"tcp-queries":            "Number of questions received over TCP",
	"tcp4-answers-bytes":     "Total number of answer bytes sent over TCPv4 (since 4.0.0)",
	"tcp4-answers":           "Number of answers sent out over TCPv4",
	"tcp4-queries":           "Number of questions received over TCPv4",
	"tcp6-answers-bytes":     "Total number of answer bytes sent over TCPv6 (since 4.0.0)",
	"tcp6-answers":           "Number of answers sent out over TCPv6",
	"tcp6-queries":           "Number of questions received over TCPv6",
	"timedout-questions":     "Amount of packets that were dropped because they had to wait too long internally",
	"udp-answers-bytes":      "Total number of answer bytes sent over UDP",
	"udp-answers":            "Number of answers sent out over UDP",
	"udp-do-queries":         "Number of queries received with the DO (DNSSEC OK) bit set",
	"udp-in-errors":          "Number of packets, received faster than the OS could process them",
	"udp-noport-errors":      "Number of UDP packets where an ICMP response was received that the remote port was not listening",
	"udp-queries":            "Number of questions received over UDP",
	"udp-recvbuf-errors":     "Number of errors caused in the UDP receive buffer",
	"udp-sndbuf-errors":      "Number of errors caused in the UDP send buffer",
	"udp4-answers-bytes":     "Total number of answer bytes sent over UDPv4 (Since 4.0.0)",
	"udp4-answers":           "Number of answers sent out over UDPv4",
	"udp4-queries":           "Number of questions received over UDPv4",
	"udp6-answers-bytes":     "Total number of answer bytes sent over UDPv6 (Since 4.0.0)",
	"udp6-answers":           "Number of answers sent out over UDPv6",
	"udp6-queries":           "Number of questions received over UDPv6",
	"uptime":                 "Uptime in seconds of the daemon",
	"user-msec":              "Number of milliseconds spend in CPU 'user' time",
}

var recursorMetricDescriptions = map[string]string{
	"all-outqueries":              "counts the number of outgoing UDP queries since starting",
	"answers-slow":                "counts the number of queries answered after 1 second",
	"answers0-1":                  "counts the number of queries answered within 1 millisecond",
	"answers1-10":                 "counts the number of queries answered within 10 milliseconds",
	"answers10-100":               "counts the number of queries answered within 100 milliseconds",
	"answers100-1000":             "counts the number of queries answered within 1 second",
	"auth4-answers-slow":          "counts the number of queries answered by auth4s after 1 second (4.0)",
	"auth4-answers0-1":            "counts the number of queries answered by auth4s within 1 millisecond (4.0)",
	"auth4-answers1-10":           "counts the number of queries answered by auth4s within 10 milliseconds (4.0)",
	"auth4-answers10-100":         "counts the number of queries answered by auth4s within 100 milliseconds (4.0)",
	"auth4-answers100-1000":       "counts the number of queries answered by auth4s within 1 second (4.0)",
	"auth6-answers-slow":          "counts the number of queries answered by auth6s after 1 second (4.0)",
	"auth6-answers0-1":            "counts the number of queries answered by auth6s within 1 millisecond (4.0)",
	"auth6-answers1-10":           "counts the number of queries answered by auth6s within 10 milliseconds (4.0)",
	"auth6-answers10-100":         "counts the number of queries answered by auth6s within 100 milliseconds (4.0)",
	"auth6-answers100-1000":       "counts the number of queries answered by auth6s within 1 second (4.0)",
	"cache-bytes":                 "size of the cache in bytes (since 3.3.1)",
	"cache-entries":               "shows the number of entries in the cache",
	"cache-hits":                  "counts the number of cache hits since starting, this does not include hits that got answered from the packet-cache",
	"cache-misses":                "counts the number of cache misses since starting",
	"case-mismatches":             "counts the number of mismatches in character case since starting",
	"chain-resends":               "number of queries chained to existing outstanding query",
	"client-parse-errors":         "counts number of client packets that could not be parsed",
	"concurrent-queries":          "shows the number of MThreads currently running",
	"dlg-only-drops":              "number of records dropped because of delegation only setting",
	"dnssec-queries":              "number of queries received with the DO bit set",
	"dnssec-result-bogus":         "number of DNSSEC validations that had the Bogus state",
	"dnssec-result-indeterminate": "number of DNSSEC validations that had the Indeterminate state",
	"dnssec-result-insecure":      "number of DNSSEC validations that had the Insecure state",
	"dnssec-result-nta":           "number of DNSSEC validations that had the NTA (negative trust anchor) state",
	"dnssec-result-secure":        "number of DNSSEC validations that had the Secure state",
	"dnssec-validations":          "number of DNSSEC validations performed",
	"dont-outqueries":             "number of outgoing queries dropped because of 'dont-query' setting (since 3.3)",
	"edns-ping-matches":           "number of servers that sent a valid EDNS PING response",
	"edns-ping-mismatches":        "number of servers that sent an invalid EDNS PING response",
	"failed-host-entries":         "number of servers that failed to resolve",
	"ignored-packets":             "counts the number of non-query packets received on server sockets that should only get query packets",
	"ipv6-outqueries":             "number of outgoing queries over IPv6",
	"ipv6-questions":              "counts all end-user initiated queries with the RD bit set, received over IPv6 UDP",
	"malloc-bytes":                "returns the number of bytes allocated by the process (broken, always returns 0)",
	"max-mthread-stack":           "maximum amount of thread stack ever used",
	"negcache-entries":            "shows the number of entries in the negative answer cache",
	"no-packet-error":             "number of erroneous received packets",
	"noedns-outqueries":           "number of queries sent out without EDNS",
	"noerror-answers":             "counts the number of times it answered NOERROR since starting",
	"noping-outqueries":           "number of queries sent out without ENDS PING",
	"nsset-invalidations":         "number of times an nsset was dropped because it no longer worked",
	"nsspeeds-entries":            "shows the number of entries in the NS speeds map",
	"nxdomain-answers":            "counts the number of times it answered NXDOMAIN since starting",
	"outgoing-timeouts":           "counts the number of timeouts on outgoing UDP queries since starting",
	"outgoing4-timeouts":          "counts the number of timeouts on outgoing UDP IPv4 queries since starting (since 4.0)",
	"outgoing6-timeouts":          "counts the number of timeouts on outgoing UDP IPv6 queries since starting (since 4.0)",
	"over-capacity-drops":         "questions dropped because over maximum concurrent query limit (since 3.2)",
	"packetcache-bytes":           "size of the packet cache in bytes (since 3.3.1)",
	"packetcache-entries":         "size of packet cache (since 3.2)",
	"packetcache-hits":            "packet cache hits (since 3.2)",
	"packetcache-misses":          "packet cache misses (since 3.2)",
	"policy-drops":                "packets dropped because of (Lua) policy decision",
	"policy-result-noaction":      "packets that were not actioned upon by the RPZ/filter engine",
	"policy-result-drop":          "packets that were dropped by the RPZ/filter engine",
	"policy-result-nxdomain":      "packets that were replied to with NXDOMAIN by the RPZ/filter engine",
	"policy-result-nodata":        "packets that were replied to with no data by the RPZ/filter engine",
	"policy-result-truncate":      "packets that were forced to TCP by the RPZ/filter engine",
	"policy-result-custom":        "packets that were sent a custom answer by the RPZ/filter engine",
	"qa-latency":                  "shows the current latency average, in microseconds, exponentially weighted over past 'latency-statistic-size' packets",
	"questions":                   "counts all end-user initiated queries with the RD bit set",
	"resource-limits":             "counts number of queries that could not be performed because of resource limits",
	"security-status":             "security status based on security polling",
	"server-parse-errors":         "counts number of server replied packets that could not be parsed",
	"servfail-answers":            "counts the number of times it answered SERVFAIL since starting",
	"spoof-prevents":              "number of times PowerDNS considered itself spoofed, and dropped the data",
	"sys-msec":                    "number of CPU milliseconds spent in 'system' mode",
	"tcp-client-overflow":         "number of times an IP address was denied TCP access because it already had too many connections",
	"tcp-clients":                 "counts the number of currently active TCP/IP clients",
	"tcp-outqueries":              "counts the number of outgoing TCP queries since starting",
	"tcp-questions":               "counts all incoming TCP queries (since starting)",
	"throttle-entries":            "shows the number of entries in the throttle map",
	"throttled-out":               "counts the number of throttled outgoing UDP queries since starting",
	"throttled-outqueries":        "idem to throttled-out",
	"too-old-drops":               "questions dropped that were too old",
	"unauthorized-tcp":            "number of TCP questions denied because of allow-from restrictions",
	"unauthorized-udp":            "number of UDP questions denied because of allow-from restrictions",
	"unexpected-packets":          "number of answers from remote servers that were unexpected (might point to spoofing)",
	"unreachables":                "number of times nameservers were unreachable since starting",
	"uptime":                      "number of seconds process has been running (since 3.1.5)",
	"user-msec":                   "number of CPU milliseconds spent in 'user' mode",
}

// NewExporter creates a new PowerDNS to Prometheus metrics exporter.
func NewExporter(pdnsControlSocket string, rateLimiterEnabled bool, rateLimiterCooldown time.Duration, isRecursor bool, collectionTimeout time.Duration, tmpDirPrefix string, localSocketMode uint) *Exporter {
	splitAddr := strings.Split(pdnsControlSocket, ":")
	proto := splitAddr[0]
	addr := splitAddr[1]

	return &Exporter{
		proto,
		addr,
		isRecursor,
		collectionTimeout,
		tmpDirPrefix,
		localSocketMode,
		prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace:   namespace,
			Subsystem:   subsystem,
			Name:        "last_scrape_error",
			Help:        "1 if the last scrape failed for any reason",
			ConstLabels: prometheus.Labels{"controlsocket": addr},
		}),
		rateLimiterEnabled,
		rateLimiterCooldown,
		time.Time{},
		make(map[string]float64),
		sync.RWMutex{},
	}
}

// Exporter implements prometheus.Collector for PowerDNS
// nolint: aligncheck
type Exporter struct {
	// Connect config
	controlProto string
	controlAddr  string
	// Should the recursor protocol be used?
	isRecursor        bool
	collectionTimeout time.Duration
	tmpDirPrefix      string
	localSocketMode   uint
	// Informational metrics
	error prometheus.Gauge

	// Rate limiter confit
	rateLimiterEnabled  bool
	rateLimiterCooldown time.Duration

	lastPoll time.Time // Time of last poll

	metricCache map[string]float64 // Metric cache
	mtx         sync.RWMutex
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

	var subsystem string
	if e.isRecursor {
		subsystem = "recursor"
	} else {
		subsystem = "authoritative"
	}

	// Emit metrics
	for key, value := range e.metricCache {
		var help string
		var ok bool
		if !e.isRecursor {
			help, ok = authMetricDescriptions[key]
		} else {
			help, ok = recursorMetricDescriptions[key]
		}
		if !ok {
			help = fmt.Sprintf("unknown metric: %s", key)
		}

		// Post-process name to prometheus style
		escapedKey := strings.Replace(key, "-", "_", -1)

		desc := prometheus.NewDesc(fmt.Sprintf("%s_%s_%s", namespace, subsystem, escapedKey), help, nil, prometheus.Labels{"controlsocket": e.controlAddr})
		ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, value)
	}

	e.error.Collect(ch)
}

// nolint: gocyclo
func (e *Exporter) scrape(ch chan<- prometheus.Metric) {
	// Check if poll allowed
	if (time.Since(e.lastPoll) < e.rateLimiterCooldown) && e.rateLimiterEnabled {
		log.Debugln("Rate-limiting request - cached data will be used.")
		return
	}
	log.Debugln("Cooldown expired, getting new data")
	e.lastPoll = time.Now()

	e.error.Set(0)

	collectionStart := time.Now()

	// Setup the dialer - since we need to support unixgram to support the
	// recursor this requires some special casing.
	dialer := net.Dialer{
		Deadline: collectionStart.Add(e.collectionTimeout),
	}

	// For unixgram sockets, these are potentially separate.
	var writeConn, listenConn net.Conn

	switch e.controlProto {
	case netUnixgram:
		tempFile, err := ioutil.TempFile(e.tmpDirPrefix, "lsock")
		if err != nil {
			log.Errorln("Could not create temporary filename:", err)
			e.error.Set(1)
			return
		}
		tempFileName := tempFile.Name()
		if err := tempFile.Close(); err != nil {
			log.Errorln("Could not close temporary file:", err)
			e.error.Set(1)
			return
		}
		if err := os.Remove(tempFileName); err != nil {
			log.Errorln("Could not remove temporary file:", err)
			e.error.Set(1)
			return
		}
		listenAddr := &net.UnixAddr{Name: tempFileName, Net: netUnixgram}
		defer os.Remove(tempFileName) // nolint: errcheck
		dialer.LocalAddr = listenAddr
	}

	conn, err := dialer.Dial(e.controlProto, e.controlAddr)
	if err != nil {
		log.Errorln("connect:", err)
		e.error.Set(1)
		return
	}
	writeConn = conn
	// If no listenConn by now, use writeConn
	if listenConn == nil {
		listenConn = writeConn
	}
	defer writeConn.Close() // nolint: errcheck

	// Post-dial setup
	switch e.controlProto {
	case netUnixgram:
		if err := os.Chmod(dialer.LocalAddr.(*net.UnixAddr).Name, os.FileMode(e.localSocketMode)); err != nil {
			log.Errorln("Could not set permissions on local response socket:", err)
			e.error.Set(1)
			return
		}

	}

	var buf bytes.Buffer
	// Read the response asynchronously so we can support both unix and unixgram
	// protocols (authoritative and recursor respectively)
	readResult := make(chan int, 1)
	go func() {
		var err error
		for {
			var n int
			var recvBuf [16384]byte
			n, err = listenConn.Read(recvBuf[:])
			log.Debugln("Read", n, "bytes from socket")
			if err != io.EOF && err != nil {
				log.Errorln("read:", err)
				readResult <- 1
				return
			} else if err == io.EOF {
				readResult <- 0
				return
			}
			if n == 0 {
				readResult <- 1
				return
			}
			_, err = buf.Write(recvBuf[:n])
			if err != nil {
				log.Errorln("buf.Write:", err)
				readResult <- 1
				return
			}
			// Unixgram from PDNS sends exactly 1 packet
			if e.controlProto == netUnixgram {
				readResult <- 0
				return
			}
		}
	}()

	if !e.isRecursor {
		if _, err := writeConn.Write([]byte("SHOW *\n")); err != nil {
			log.Errorln("write:", err)
			e.error.Set(1)
			return
		}
	} else {
		if _, err := writeConn.Write([]byte("get-all\n")); err != nil {
			log.Errorln("write:", err)
			e.error.Set(1)
			return
		}
	}

	timeoutCh := time.After(e.collectionTimeout)

	select {
	case <-timeoutCh:
		log.Errorln("timeout waiting for powerdns response")
		e.error.Set(1)
		return
	case result := <-readResult:
		if result > 0 {
			log.Errorln("error in read response: status", result)
			e.error.Set(1)
			return
		}
	}

	var metricStrings []string

	if !e.isRecursor {
		metricStrings = strings.Split(buf.String(), ",")
	} else {
		metricStrings = strings.Split(buf.String(), "\n")
	}

	// Update the internal map
	e.mtx.Lock()
	defer e.mtx.Unlock()
	for _, rawMetric := range metricStrings {
		// Last metric always produces a blank value
		if len(rawMetric) == 0 {
			continue
		}

		var vals []string
		if !e.isRecursor {
			// Auth uses equals
			vals = strings.Split(rawMetric, "=")
		} else {
			// Recursor uses tabs
			vals = strings.Split(rawMetric, "\t")
		}

		if len(vals) != 2 {
			log.Errorln("process: did not get a pair of values")
			e.error.Set(1)
			return
		}

		key := vals[0]   // Metric name
		value := vals[1] // Metric value

		// Post process value to prometheus format
		prometheusValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.Errorln(err)
			e.error.Set(1)
			return
		}

		e.metricCache[key] = prometheusValue
	}
}

func main() {
	flag.Parse()

	if *printVersion {
		fmt.Println(Version)
		os.Exit(0)
	}

	log.Infoln("PowerDNS Exporter:", Version)

	controlSockets := strings.Split(*pdnsControlSocket, ",")
	for _, addr := range controlSockets {
		addressSpec := strings.SplitN(addr, ":", 2)
		exporterType := addressSpec[0]
		controlSocket := addressSpec[1]

		var isRecursor bool
		switch exporterType {
		case exportAuthoritative:
			isRecursor = false
		case exportRecursor:
			isRecursor = true
		default:
			log.Fatalln("Unknown process type specified:", exporterType, addr)
		}
		ex := NewExporter(controlSocket, *rateLimitUpdates, *minCooldown, isRecursor, *collectionTimeout, *tmpDirPrefix, *localSocketMode)
		prometheus.MustRegister(ex)
		log.Infoln("Registered new exporter for", exporterType, "at", controlSocket)
	}

	router := httprouter.New()
	router.Handler("GET", *metricsPath, promhttp.Handler())

	router.GET("/", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		defer r.Body.Close() // nolint: errcheck, gas
		// nolint: errcheck, gas
		w.Write([]byte(`<html>
			<head><title>PowerDNS exporter</title></head>
			<body>
			<h1>PowerDNS exporter</h1>
			<p><a href="` + *metricsPath + `">Metrics</a></p>
			</body>
			</html>`))
	})

	log.Infof("Starting pdns_exporter %s at %s", Version, *listenAddress)
	err := http.ListenAndServe(*listenAddress, router)
	if err != nil {
		log.Fatal(err)
	}
}
