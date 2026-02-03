// Unbound Prometheus Exporter
// Exports Unbound DNS statistics as Prometheus metrics via Unix socket.
// Inspired by github.com/ar51an/unbound-exporter
// License: MIT

package main

import (
	"bufio"
	"context"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
)

const (
	namespace = "unbound"
	subsystem = ""
)

// Configuration holds all application configuration
type Configuration struct {
	ListenAddress string
	MetricsPath   string
	SocketPath    string
	LogLevel      string
	Timeout       time.Duration
}

// Logger wraps standard log with levels for Go 1.19 compatibility
type Logger struct {
	debug bool
	info  bool
	warn  bool
	error bool
}

// NewLogger creates a new logger with the specified level
func NewLogger(level string) *Logger {
	l := &Logger{}
	switch strings.ToLower(level) {
	case "debug":
		l.debug, l.info, l.warn, l.error = true, true, true, true
	case "info":
		l.info, l.warn, l.error = true, true, true
	case "warn", "warning":
		l.warn, l.error = true, true
	case "error":
		l.error = true
	default:
		l.info, l.warn, l.error = true, true, true
	}
	return l
}

func (l *Logger) Debug(msg string, keyvals ...interface{}) {
	if l.debug {
		log.Printf("[DEBUG] %s %s", msg, formatKeyVals(keyvals...))
	}
}

func (l *Logger) Info(msg string, keyvals ...interface{}) {
	if l.info {
		log.Printf("[INFO] %s %s", msg, formatKeyVals(keyvals...))
	}
}

func (l *Logger) Warn(msg string, keyvals ...interface{}) {
	if l.warn {
		log.Printf("[WARN] %s %s", msg, formatKeyVals(keyvals...))
	}
}

func (l *Logger) Error(msg string, keyvals ...interface{}) {
	if l.error {
		log.Printf("[ERROR] %s %s", msg, formatKeyVals(keyvals...))
	}
}

func formatKeyVals(keyvals ...interface{}) string {
	if len(keyvals) == 0 {
		return ""
	}
	var parts []string
	for i := 0; i < len(keyvals); i += 2 {
		if i+1 < len(keyvals) {
			parts = append(parts, fmt.Sprintf("%v=%v", keyvals[i], keyvals[i+1]))
		}
	}
	return strings.Join(parts, " ")
}

// UnboundClient handles connections to Unbound
type UnboundClient struct {
	socketPath string
	timeout    time.Duration
	logger     *Logger
}

// MetricDefinition defines a Prometheus metric
type MetricDefinition struct {
	Name        string
	Help        string
	Labels      []string
	MetricType  prometheus.ValueType
	Pattern     *regexp.Regexp
	Transformer func(string, []string) (float64, []string, error)
}

// Exporter implements the Prometheus collector interface
type Exporter struct {
	client  *UnboundClient
	metrics map[string]*MetricDefinition
	logger  *Logger
}

// NewUnboundClient creates a new Unbound client
func NewUnboundClient(socketPath string, timeout time.Duration, logger *Logger) *UnboundClient {
	return &UnboundClient{
		socketPath: socketPath,
		timeout:    timeout,
		logger:     logger,
	}
}

// Query sends a command to Unbound and returns the response
func (c *UnboundClient) Query(ctx context.Context, command string) ([]string, error) {
	conn, err := net.DialTimeout("unix", c.socketPath, c.timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to unbound socket %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	// Set deadline for the entire operation
	deadline, ok := ctx.Deadline()
	if ok {
		conn.SetDeadline(deadline)
	}

	// Send command
	_, err = conn.Write([]byte(command + "\n"))
	if err != nil {
		return nil, fmt.Errorf("failed to send command to unbound: %w", err)
	}

	// Read response
	var lines []string
	scanner := bufio.NewScanner(conn)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line != "" {
			lines = append(lines, line)
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("failed to read response from unbound: %w", err)
	}

	return lines, nil
}

// parseFloat safely converts a string to float64
func parseFloat(s string) (float64, error) {
	if s == "" {
		return 0, nil
	}
	return strconv.ParseFloat(s, 64)
}

// formatUptime converts seconds to human readable format
func formatUptime(seconds float64) string {
	duration := time.Duration(seconds) * time.Second
	days := int(duration.Hours()) / 24
	hours := int(duration.Hours()) % 24
	minutes := int(duration.Minutes()) % 60

	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// formatBucket formats response time bucket labels exactly like 1.0 dashboard
func formatBucket(labelValue string) string {
	value, err := parseFloat(labelValue)
	if err != nil {
		return labelValue
	}
	
	// Convert to microseconds and format like the 1.0 dashboard
	microseconds := value * 1000000
	
	if microseconds == 0 {
		return "0 µs"
	} else if microseconds >= 1000000 {
		// Convert to seconds for very large values  
		seconds := microseconds / 1000000
		return fmt.Sprintf("%.0f s", seconds)
	} else if microseconds >= 1000 {
		// Convert to milliseconds for mid-range values
		ms := microseconds / 1000
		return fmt.Sprintf("%.0f ms", ms)
	} else {
		// Keep as microseconds for small values
		return fmt.Sprintf("%.0f µs", microseconds)
	}
}

// getMetricDefinitions returns all metric definitions
func getMetricDefinitions() map[string]*MetricDefinition {
	return map[string]*MetricDefinition{
		// Simple counter metrics
		"total.num.queries": {
			Name:       "queries_total",
			Help:       "Total number of DNS queries received",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.num.cachehits": {
			Name:       "cache_hit_total",
			Help:       "Total number of queries answered from cache",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.num.cachemiss": {
			Name:       "cache_miss_total",
			Help:       "Total number of queries that needed recursive processing",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.num.prefetch": {
			Name:       "prefetch_total",
			Help:       "Total number of cache prefetches performed",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.num.expired": {
			Name:       "expired_total",
			Help:       "Total number of queries served from expired cache entries",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		// Gauge metrics
		"total.requestlist.avg": {
			Name:       "request_list_avg",
			Help:       "Average number of requests in the request list",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.requestlist.max": {
			Name:       "request_list_max",
			Help:       "Maximum size attained by request list",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.recursion.time.avg": {
			Name:       "recursion_time_avg_seconds",
			Help:       "Average time to answer recursive queries in seconds",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"total.recursion.time.median": {
			Name:       "recursion_time_median_seconds",
			Help:       "Median time to answer recursive queries in seconds",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		// Protocol counters
		"num.query.tcpout": {
			Name:       "query_tcpout_count",
			Help:       "Total number of outgoing TCP queries",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"num.query.udpout": {
			Name:       "query_udpout_count",
			Help:       "Total number of outgoing UDP queries",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"num.query.ipv6": {
			Name:       "query_ipv6_count",
			Help:       "Total number of IPv6 queries",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		// Security metrics
		"num.answer.secure": {
			Name:       "answer_secure_count",
			Help:       "Total number of secure answers (DNSSEC)",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"num.answer.bogus": {
			Name:       "answer_bogus_count",
			Help:       "Total number of bogus answers",
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		// Cache metrics
		"msg.cache.count": {
			Name:       "msg_cache_count",
			Help:       "Number of entries in the message cache",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"rrset.cache.count": {
			Name:       "rrset_cache_count",
			Help:       "Number of entries in the RRset cache",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"infra.cache.count": {
			Name:       "infra_cache_count",
			Help:       "Number of entries in the infrastructure cache",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
		"key.cache.count": {
			Name:       "key_cache_count",
			Help:       "Number of entries in the key cache",
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, nil, err
			},
		},
	}
}

// getPatternMetrics returns metrics that match patterns
func getPatternMetrics() map[*regexp.Regexp]*MetricDefinition {
	return map[*regexp.Regexp]*MetricDefinition{
		// Thread metrics
		regexp.MustCompile(`^thread(\d+)\.requestlist\.current\.user$`): {
			Name:       "request_list_current_user",
			Help:       "Current size of request list per thread",
			Labels:     []string{"thread"},
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, []string{matches[1]}, err
			},
		},
		// Uptime with formatted label
		regexp.MustCompile(`^time\.up$`): {
			Name:       "time_up_seconds",
			Help:       "Unbound server uptime in seconds",
			Labels:     []string{"uptime"},
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, _ []string) (float64, []string, error) {
				v, err := parseFloat(value)
				if err != nil {
					return 0, nil, err
				}
				formatted := formatUptime(v)
				return v, []string{formatted}, nil
			},
		},
		// Memory cache metrics
		regexp.MustCompile(`^mem\.cache\.([a-z]+)$`): {
			Name:       "memory_caches_bytes",
			Help:       "Memory used by cache in bytes",
			Labels:     []string{"cache"},
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, []string{matches[1]}, err
			},
		},
		// Memory module metrics
		regexp.MustCompile(`^mem\.mod\.([a-z]+)$`): {
			Name:       "memory_modules_bytes",
			Help:       "Memory used by modules in bytes",
			Labels:     []string{"module"},
			MetricType: prometheus.GaugeValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, []string{matches[1]}, err
			},
		},
		// Query type metrics
		regexp.MustCompile(`^num\.query\.type\.([A-Z0-9]+)$`): {
			Name:       "query_types_count",
			Help:       "Total queries by DNS record type",
			Labels:     []string{"type"},
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, []string{matches[1]}, err
			},
		},
		// Response code metrics
		regexp.MustCompile(`^num\.answer\.rcode\.([A-Z]+)$`): {
			Name:       "answer_rcodes_count",
			Help:       "Total answers by response code",
			Labels:     []string{"rcode"},
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				return v, []string{matches[1]}, err
			},
		},
		// Response time buckets with exact ordering
		regexp.MustCompile(`^histogram\.([\d\.]+)\.to\.([\d\.]+)$`): {
			Name:       "response_time_buckets",
			Help:       "Recursive queries count grouped into response time buckets",
			Labels:     []string{"bucket_order", "lower", "upper"},
			MetricType: prometheus.CounterValue,
			Transformer: func(value string, matches []string) (float64, []string, error) {
				v, err := parseFloat(value)
				if err != nil {
					return 0, nil, err
				}
				
				lower := formatBucket(matches[1])
				upper := formatBucket(matches[2])
				
				// Create bucket order based on lower bound for exact sorting
				lowerVal, _ := parseFloat(matches[1])
				bucketOrder := fmt.Sprintf("%020.9f", lowerVal) // Zero-padded for sorting
				
				return v, []string{bucketOrder, lower, upper}, nil
			},
		},
	}
}

// NewExporter creates a new Unbound exporter
func NewExporter(client *UnboundClient, logger *Logger) *Exporter {
	flatMetrics := getMetricDefinitions()
	patternMetrics := getPatternMetrics()

	// Combine all metrics
	allMetrics := make(map[string]*MetricDefinition)
	for k, v := range flatMetrics {
		allMetrics[k] = v
	}
	for pattern, def := range patternMetrics {
		def.Pattern = pattern
		allMetrics[def.Name] = def
	}

	return &Exporter{
		client:  client,
		metrics: allMetrics,
		logger:  logger,
	}
}

// Describe implements the prometheus.Collector interface
func (e *Exporter) Describe(ch chan<- *prometheus.Desc) {
	// Create descriptors for all metrics
	for _, metric := range e.metrics {
		desc := prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, metric.Name),
			metric.Help,
			metric.Labels,
			nil,
		)
		ch <- desc
	}
}

// Collect implements the prometheus.Collector interface
func (e *Exporter) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	lines, err := e.client.Query(ctx, "UBCT1 stats_noreset")
	if err != nil {
		e.logger.Error("Failed to query Unbound statistics", "error", err)
		return
	}

	e.logger.Debug("Retrieved statistics from Unbound", "lines", len(lines))

	// Parse each line
	for _, line := range lines {
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := strings.TrimSpace(parts[0])
		value := strings.TrimSpace(parts[1])

		e.processMetric(ch, key, value)
	}
}

// processMetric processes a single metric key-value pair
func (e *Exporter) processMetric(ch chan<- prometheus.Metric, key, value string) {
	// Try flat metrics first
	if metric, exists := e.metrics[key]; exists {
		metricValue, labels, err := metric.Transformer(value, nil)
		if err != nil {
			e.logger.Error("Failed to parse metric value", "key", key, "error", err)
			return
		}

		desc := prometheus.NewDesc(
			prometheus.BuildFQName(namespace, subsystem, metric.Name),
			metric.Help,
			metric.Labels,
			nil,
		)

		ch <- prometheus.MustNewConstMetric(desc, metric.MetricType, metricValue, labels...)
		return
	}

	// Try pattern metrics
	for _, metric := range e.metrics {
		if metric.Pattern != nil {
			if matches := metric.Pattern.FindStringSubmatch(key); matches != nil {
				metricValue, labels, err := metric.Transformer(value, matches)
				if err != nil {
					e.logger.Error("Failed to parse pattern metric value", "key", key, "error", err)
					return
				}

				desc := prometheus.NewDesc(
					prometheus.BuildFQName(namespace, subsystem, metric.Name),
					metric.Help,
					metric.Labels,
					nil,
				)

				ch <- prometheus.MustNewConstMetric(desc, metric.MetricType, metricValue, labels...)
				return
			}
		}
	}
}

// createRootCommand creates the root cobra command
func createRootCommand() *cobra.Command {
	config := &Configuration{
		ListenAddress: "0.0.0.0:9167",
		MetricsPath:   "/metrics",
		SocketPath:    "/run/unbound.ctl",
		LogLevel:      "info",
		Timeout:       5 * time.Second,
	}

	cmd := &cobra.Command{
		Use:   "unbound-exporter",
		Short: "Secure Prometheus exporter for Unbound DNS server (Go 1.19 compatible)",
		Long: `A secure and minimal Prometheus exporter for Unbound DNS server.
Connects to Unbound via Unix socket and exports DNS performance metrics.

Compatible with Go 1.19+ - uses standard log instead of slog.
Only essential dependencies: Prometheus client + Cobra CLI framework.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runExporter(config)
		},
	}

	cmd.Flags().StringVarP(&config.ListenAddress, "listen-address", "l", config.ListenAddress, "Address to listen on")
	cmd.Flags().StringVarP(&config.MetricsPath, "metrics-path", "m", config.MetricsPath, "Path to expose metrics")
	cmd.Flags().StringVarP(&config.SocketPath, "socket-path", "s", config.SocketPath, "Path to Unbound control socket")
	cmd.Flags().StringVar(&config.LogLevel, "log-level", config.LogLevel, "Log level (debug, info, warn, error)")
	cmd.Flags().DurationVarP(&config.Timeout, "timeout", "t", config.Timeout, "Timeout for Unbound queries")

	return cmd
}

// runExporter runs the exporter with the given configuration
func runExporter(config *Configuration) error {
	logger := NewLogger(config.LogLevel)

	logger.Info("Starting Unbound exporter",
		"listen_address", config.ListenAddress,
		"metrics_path", config.MetricsPath,
		"socket_path", config.SocketPath,
		"timeout", config.Timeout,
	)

	// Verify socket exists and is accessible
	if _, err := os.Stat(config.SocketPath); os.IsNotExist(err) {
		logger.Error("Unbound socket does not exist", "socket_path", config.SocketPath)
		return fmt.Errorf("unbound socket does not exist: %s", config.SocketPath)
	}

	// Create client and exporter
	client := NewUnboundClient(config.SocketPath, config.Timeout, logger)
	exporter := NewExporter(client, logger)

	// Test connection
	ctx, cancel := context.WithTimeout(context.Background(), config.Timeout)
	defer cancel()
	_, err := client.Query(ctx, "UBCT1 stats_noreset")
	if err != nil {
		logger.Error("Failed to connect to Unbound - check socket path and permissions", "error", err)
		return fmt.Errorf("failed to connect to Unbound: %w", err)
	}
	logger.Info("Successfully connected to Unbound")

	// Register exporter
	registry := prometheus.NewRegistry()
	registry.MustRegister(exporter)

	// Setup HTTP handlers
	mux := http.NewServeMux()
	mux.Handle(config.MetricsPath, promhttp.HandlerFor(registry, promhttp.HandlerOpts{
		ErrorHandling: promhttp.ContinueOnError,
	}))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		fmt.Fprintf(w, `<!DOCTYPE html>
<html>
<head><title>Secure Unbound Exporter (Go 1.19)</title></head>
<body>
<h1>Secure Unbound DNS Exporter</h1>
<p><a href="%s">Metrics</a></p>
<p>Go 1.19 compatible - minimal dependencies, securely monitoring Unbound DNS performance</p>
<p><strong>Dependencies:</strong> Prometheus client + Cobra CLI (both trusted)</p>
</body>
</html>`, config.MetricsPath)
	})

	// Create HTTP server
	server := &http.Server{
		Addr:         config.ListenAddress,
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  60 * time.Second,
	}

	// Setup graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigChan
		logger.Info("Received shutdown signal", "signal", sig)
		
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		
		if err := server.Shutdown(ctx); err != nil {
			logger.Error("Failed to shutdown server gracefully", "error", err)
		}
	}()

	logger.Info("Server starting", "address", config.ListenAddress)
	if err := server.ListenAndServe(); err != http.ErrServerClosed {
		return fmt.Errorf("server failed: %w", err)
	}

	logger.Info("Server shutdown complete")
	return nil
}

func main() {
	cmd := createRootCommand()
	if err := cmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}