package telemetry

import (
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"
)

const meterName = "synapse/http"

type httpMetrics struct {
	requestCount  metric.Int64Counter
	durationHisto metric.Float64Histogram
}

var (
	metrics     *httpMetrics
	metricsOnce sync.Once
)

func initHTTPMetrics() {
	metricsOnce.Do(func() {
		meter := otel.Meter(meterName)

		counter, err := meter.Int64Counter("otel_http_requests_total",
			metric.WithDescription("Total number of HTTP requests"),
		)
		if err != nil {
			return
		}

		histo, err := meter.Float64Histogram("otel_http_request_duration_seconds",
			metric.WithDescription("Duration of HTTP requests in seconds"),
			metric.WithUnit("s"),
		)
		if err != nil {
			return
		}

		metrics = &httpMetrics{
			requestCount:  counter,
			durationHisto: histo,
		}
	})
}

// MetricsMiddleware returns a Gin middleware that records HTTP request count
// and duration with method, path, and status code labels.
func MetricsMiddleware() gin.HandlerFunc {
	if metrics == nil {
		initHTTPMetrics()
	}

	return func(c *gin.Context) {
		start := time.Now()
		path := c.FullPath()
		if path == "" {
			path = "unknown"
		}

		c.Next()

		if metrics == nil {
			return
		}

		status := c.Writer.Status()
		duration := time.Since(start).Seconds()

		attrs := []attribute.KeyValue{
			attribute.String("http.method", c.Request.Method),
			attribute.String("http.route", path),
			attribute.Int("http.status_code", status),
		}

		metrics.requestCount.Add(c.Request.Context(), 1, metric.WithAttributes(attrs...))
		metrics.durationHisto.Record(c.Request.Context(), duration, metric.WithAttributes(attrs...))
	}
}

// RecordMetricAttrs returns the common attributes for a metric observation.
// This can be used by other middleware or handlers that need to record
// custom metrics beyond the default HTTP middleware.
func RecordMetricAttrs(c *gin.Context) []attribute.KeyValue {
	path := c.FullPath()
	if path == "" {
		path = "unknown"
	}
	return []attribute.KeyValue{
		attribute.String("http.method", c.Request.Method),
		attribute.String("http.route", path),
		attribute.Int("http.status_code", c.Writer.Status()),
	}
}
