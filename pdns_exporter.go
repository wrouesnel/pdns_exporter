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
)

const namespace = "pdns"
const subsystem = "exporter"

var (
	Version = "0.0.0.dev"

	listenAddress     = flag.String("web.listen-address", ":34576", "Address on which to expose metrics and web interface.")
	metricsPath       = flag.String("web.telemetry-path", "/metrics", "Path under which to expose metrics.")

	pdnsControlSocket = flag.String("collector.powerdns.socket", "unix:/var/run/pdns.controlsocket", "Connect string to control socket")
)

func NewExporter(pdnsControlSocket string) *Exporter {
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
	}
}

type Exporter struct {
	controlProto string
	controlAddr  string
	error prometheus.Gauge
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
	e.scrape(ch)
	e.error.Collect(ch)
}

func (e *Exporter) scrape(ch chan<- prometheus.Metric) {
	e.error.Set(0)
	conn, err := net.Dial(e.controlProto, e.controlAddr)
	if err != nil {
		log.Errorln("connect:",err)
		e.error.Set(1)
		return
	}
	defer conn.Close()

	// Get the metrics
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

	for _, rawMetric := range metricStrings {
		// Last metric always produces a blank value
		if len(rawMetric) == 0 {
			continue
		}

		vals := strings.Split(rawMetric, "=")
		if len(vals) != 2 {
			log.Errorln("process: did not get a pair of values")
			e.error.Set(1)
			return
		}

		key := vals[0]	// Metric name
		value := vals[1]	// Metric value

		// Post-process name ot prometheus style
		prometheusKey := strings.Replace(key, "-", "_", -1)

		desc := prometheus.NewDesc(fmt.Sprintf("%s_%s", namespace, prometheusKey),
			fmt.Sprintf("%s_%s", namespace, prometheusKey), nil, nil )

		// Post process to prometheus format
		prometheusValue, err := strconv.ParseFloat(value, 64)
		if err != nil {
			log.Errorln(err)
			e.error.Set(1)
			return
		}

		// Emit as untyped value
		ch <- prometheus.MustNewConstMetric(desc, prometheus.UntypedValue, prometheusValue)
	}
}

func main() {
	flag.Parse()

	ex := NewExporter(*pdnsControlSocket)
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