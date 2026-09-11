// Browser OpenTelemetry bootstrap. Imported first from main.ts so the global
// fetch is instrumented before any app code runs. No-ops unless the server
// rendered the otel-enabled meta tag (Dashboard handler).
import { CompositePropagator, W3CBaggagePropagator, W3CTraceContextPropagator } from '@opentelemetry/core';
import { registerInstrumentations } from '@opentelemetry/instrumentation';
import { DocumentLoadInstrumentation } from '@opentelemetry/instrumentation-document-load';
import { FetchInstrumentation } from '@opentelemetry/instrumentation-fetch';
import { resourceFromAttributes } from '@opentelemetry/resources';
import { BatchSpanProcessor } from '@opentelemetry/sdk-trace-base';
import { WebTracerProvider } from '@opentelemetry/sdk-trace-web';
import { OTLPTraceExporter } from '@opentelemetry/exporter-trace-otlp-http';
import { ATTR_SERVICE_NAME, ATTR_SERVICE_VERSION } from '@opentelemetry/semantic-conventions';

function meta(name: string): string {
    return document.querySelector<HTMLMetaElement>('meta[name="' + name + '"]')?.content ?? '';
}

const enabled = meta('otel-enabled');
if (enabled === 'true' || enabled === '1') {
    const endpoint = meta('otel-browser-endpoint');

    // Export only when a collector URL is configured. Without one we still
    // register the provider + fetch instrumentation: same-origin /api requests
    // get a W3C traceparent, which the Go otelgin middleware extracts, so the
    // backend trace stays joined to the browser even with no browser exporter.
    const spanProcessors = endpoint
        ? [new BatchSpanProcessor(new OTLPTraceExporter({ url: endpoint }), { scheduledDelayMillis: 500 })]
        : [];

    const provider = new WebTracerProvider({
        resource: resourceFromAttributes({
            [ATTR_SERVICE_NAME]: 'synapse-web',
            [ATTR_SERVICE_VERSION]: meta('app-version') || '0.0.0',
        }),
        spanProcessors,
    });

    provider.register({
        propagator: new CompositePropagator({
            propagators: [new W3CTraceContextPropagator(), new W3CBaggagePropagator()],
        }),
    });

    registerInstrumentations({
        instrumentations: [
            new DocumentLoadInstrumentation(),
            new FetchInstrumentation({
                // Don't trace the exporter's own POST to the collector.
                ignoreUrls: [/\/v1\/traces/],
            }),
        ],
    });
    // ponytail: default StackContextManager is enough — no manual spans across
    // await are created. Switch to ZoneContextManager if that changes.
}
