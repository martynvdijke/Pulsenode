package telemetry

import (
	"context"
	"log"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"time"

	"go.opentelemetry.io/contrib/bridges/otelslog"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploggrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlplog/otlploghttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/log/global"
	"go.opentelemetry.io/otel/propagation"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	"go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.26.0"
	"go.opentelemetry.io/otel/trace"
)

var Tracer trace.Tracer = trace.NewNoopTracerProvider().Tracer("synapse")

// multiHandler fans a log record out to several slog handlers. It is used to
// keep the existing handler (the logging ring buffer that backs /api/logs and
// the SSE stream) while also exporting records over OTLP.
type multiHandler struct {
	handlers []slog.Handler
}

func (m multiHandler) Enabled(ctx context.Context, level slog.Level) bool {
	for _, h := range m.handlers {
		if h.Enabled(ctx, level) {
			return true
		}
	}
	return false
}

func (m multiHandler) Handle(ctx context.Context, r slog.Record) error {
	for _, h := range m.handlers {
		if h.Enabled(ctx, r.Level) {
			_ = h.Handle(ctx, r.Clone())
		}
	}
	return nil
}

func (m multiHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithAttrs(attrs)
	}
	return multiHandler{handlers: next}
}

func (m multiHandler) WithGroup(name string) slog.Handler {
	next := make([]slog.Handler, len(m.handlers))
	for i, h := range m.handlers {
		next[i] = h.WithGroup(name)
	}
	return multiHandler{handlers: next}
}

type Providers struct {
	TracerProvider *sdktrace.TracerProvider
	MeterProvider  *metric.MeterProvider
	LoggerProvider *sdklog.LoggerProvider
}

func getOTLPEndpoint(dbEndpoint string) string {
	if dbEndpoint != "" {
		return dbEndpoint
	}
	return os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
}

func getServiceName() string {
	if n := os.Getenv("OTEL_SERVICE_NAME"); n != "" {
		return n
	}
	return "synapse"
}

func getOTLPProtocol() string {
	p := os.Getenv("OTEL_EXPORTER_OTLP_PROTOCOL")
	if p == "" {
		return "grpc"
	}
	return p
}

func buildResource(serviceName, version string) (*resource.Resource, error) {
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	if version != "" {
		attrs = append(attrs, semconv.ServiceVersion(version))
	}
	opts := []resource.Option{
		resource.WithTelemetrySDK(),
		resource.WithAttributes(attrs...),
	}
	if ra := os.Getenv("OTEL_RESOURCE_ATTRIBUTES"); ra != "" {
		pairs := strings.Split(ra, ",")
		attrs := make([]attribute.KeyValue, 0, len(pairs))
		for _, pair := range pairs {
			parts := strings.SplitN(pair, "=", 2)
			if len(parts) == 2 {
				attrs = append(attrs, attribute.String(strings.TrimSpace(parts[0]), strings.TrimSpace(parts[1])))
			}
		}
		if len(attrs) > 0 {
			opts = append(opts, resource.WithAttributes(attrs...))
		}
	}
	return resource.New(context.Background(), opts...)
}

func configureSampler() sdktrace.Sampler {
	sampler := os.Getenv("OTEL_TRACES_SAMPLER")
	arg := os.Getenv("OTEL_TRACES_SAMPLER_ARG")

	var ratio float64 = 1.0
	if f, err := strconv.ParseFloat(arg, 64); err == nil {
		ratio = f
	}

	switch strings.ToLower(sampler) {
	case "always_on":
		return sdktrace.AlwaysSample()
	case "always_off":
		return sdktrace.NeverSample()
	case "traceidratio":
		return sdktrace.TraceIDRatioBased(ratio)
	case "parentbased_always_on":
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	case "parentbased_always_off":
		return sdktrace.ParentBased(sdktrace.NeverSample())
	case "parentbased_traceidratio":
		return sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))
	default:
		// ParentBased so an upstream traceparent sampling decision is honored
		// (a downstream service must not force-sample an unsampled parent).
		return sdktrace.ParentBased(sdktrace.AlwaysSample())
	}
}

func InitTelemetry(dbEndpoint, version string, baseHandler slog.Handler) (*Providers, error) {
	endpoint := getOTLPEndpoint(dbEndpoint)
	serviceName := getServiceName()
	protocol := getOTLPProtocol()

	// W3C TraceContext + Baggage is the OTel default today; set it explicitly
	// so otelgin/otelhttp propagation can't drift with future SDK defaults.
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{}, propagation.Baggage{},
	))

	// The exporters below are created with no options, so the SDK reads the
	// standard OTEL_EXPORTER_OTLP_* env vars. Publish the configured collector
	// so a DB/UI endpoint actually reaches them (previously it was ignored).
	if endpoint != "" {
		os.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", endpoint)
	}

	res, err := buildResource(serviceName, version)
	if err != nil {
		return nil, err
	}

	if endpoint == "" {
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res))
		otel.SetTracerProvider(tp)
		Tracer = tp.Tracer(serviceName)
		log.Printf("[telemetry] no OTEL_EXPORTER_OTLP_ENDPOINT set, using no-op exporters")
		return &Providers{TracerProvider: tp}, nil
	}

	// ── Trace provider ──────────────────────────────────────────────────────
	var traceExporter sdktrace.SpanExporter
	if protocol == "grpc" {
		traceExporter, err = otlptracegrpc.New(context.Background())
	} else {
		traceExporter, err = otlptracehttp.New(context.Background())
	}
	if err != nil {
		log.Printf("[telemetry] failed to create trace exporter: %v, falling back to noop", err)
		tp := sdktrace.NewTracerProvider(sdktrace.WithResource(res))
		otel.SetTracerProvider(tp)
		Tracer = tp.Tracer(serviceName)
		return &Providers{TracerProvider: tp}, nil
	}

	sampler := configureSampler()
	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(traceExporter, sdktrace.WithBatchTimeout(5*time.Second)),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)
	Tracer = tp.Tracer(serviceName)

	// ── Meter provider ──────────────────────────────────────────────────────
	var mp *metric.MeterProvider
	var metricExporter metric.Exporter
	if protocol == "grpc" {
		metricExporter, err = otlpmetricgrpc.New(context.Background())
	} else {
		metricExporter, err = otlpmetrichttp.New(context.Background())
	}
	if err == nil {
		mp = metric.NewMeterProvider(
			metric.WithReader(metric.NewPeriodicReader(metricExporter, metric.WithInterval(10*time.Second))),
			metric.WithResource(res),
		)
		otel.SetMeterProvider(mp)
	} else {
		log.Printf("[telemetry] failed to create metric exporter: %v, metrics disabled", err)
	}

	// ── Logger provider ─────────────────────────────────────────────────────
	var lp *sdklog.LoggerProvider
	var logExporter sdklog.Exporter
	if protocol == "grpc" {
		logExporter, err = otlploggrpc.New(context.Background())
	} else {
		logExporter, err = otlploghttp.New(context.Background())
	}
	if err == nil {
		lp = sdklog.NewLoggerProvider(
			sdklog.WithProcessor(sdklog.NewBatchProcessor(logExporter)),
			sdklog.WithResource(res),
		)
		global.SetLoggerProvider(lp)

		// Wire the OTel slog bridge with trace context injection. When a base
		// handler is supplied (the running logger, e.g. logging's ring buffer
		// that backs the Logs tab and SSE stream), tee to it so telemetry does
		// not silently disable those. Teeing only happens for an explicit base
		// handler: Go's built-in slog default routes through the std log
		// package, which can deadlock with the OTel exporter's own logging.
		logHandler := otelslog.NewHandler(serviceName,
			otelslog.WithLoggerProvider(lp),
		)
		if baseHandler != nil {
			slog.SetDefault(slog.New(multiHandler{
				handlers: []slog.Handler{baseHandler, logHandler},
			}))
		} else {
			slog.SetDefault(slog.New(logHandler))
		}
	} else {
		log.Printf("[telemetry] failed to create log exporter: %v, logs disabled", err)
	}

	log.Printf("[telemetry] initialized with OTLP endpoint: %s (protocol: %s)", endpoint, protocol)
	return &Providers{
		TracerProvider: tp,
		MeterProvider:  mp,
		LoggerProvider: lp,
	}, nil
}

func Shutdown(providers *Providers) {
	if providers == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if providers.TracerProvider != nil {
		if err := providers.TracerProvider.Shutdown(ctx); err != nil {
			log.Printf("[telemetry] tracer provider shutdown error: %v", err)
		}
	}
	if providers.MeterProvider != nil {
		if err := providers.MeterProvider.Shutdown(ctx); err != nil {
			log.Printf("[telemetry] meter provider shutdown error: %v", err)
		}
	}
	if providers.LoggerProvider != nil {
		if err := providers.LoggerProvider.Shutdown(ctx); err != nil {
			log.Printf("[telemetry] logger provider shutdown error: %v", err)
		}
	}
}

// InitTracerProvider is kept for backward compatibility. It initializes only
// the tracer provider, delegating to InitTelemetry internally.
func InitTracerProvider(dbEndpoint string) (*sdktrace.TracerProvider, error) {
	p, err := InitTelemetry(dbEndpoint, "", nil)
	if err != nil {
		return nil, err
	}
	return p.TracerProvider, nil
}

// ShutdownTracerProvider is kept for backward compatibility.
func ShutdownTracerProvider(tp *sdktrace.TracerProvider) {
	if tp == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := tp.Shutdown(ctx); err != nil {
		log.Printf("[telemetry] tracer provider shutdown error: %v", err)
	}
}
