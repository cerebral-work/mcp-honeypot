# OpenTelemetry Configuration

## SDK Setup

    def setup_telemetry(service_name, otlp_endpoint):
        resource = Resource.create({
            "service.name": service_name,
            "service.version": "0.1.0",
            "deployment.environment": "honeypot",
        })
        tracer_provider = TracerProvider(resource=resource)
        tracer_provider.add_span_processor(
            BatchSpanProcessor(OTLPSpanExporter(endpoint=otlp_endpoint, insecure=True))
        )
        trace.set_tracer_provider(tracer_provider)

        metric_reader = PeriodicExportingMetricReader(
            OTLPMetricExporter(endpoint=otlp_endpoint, insecure=True),
            export_interval_millis=15000
        )
        metrics.set_meter_provider(MeterProvider(resource=resource, metric_readers=[metric_reader]))

## Collector Config

    receivers:
      otlp:
        protocols:
          grpc:
            endpoint: 0.0.0.0:4317
          http:
            endpoint: 0.0.0.0:4318

    processors:
      batch:
        timeout: 5s
        send_batch_size: 512
      memory_limiter:
        limit_mib: 512

    exporters:
      prometheus:
        endpoint: "0.0.0.0:8889"
        namespace: mcp_honeypot
      otlp/jaeger:
        endpoint: jaeger:4317
        tls:
          insecure: true

    service:
      pipelines:
        traces:
          receivers: [otlp]
          processors: [memory_limiter, batch]
          exporters: [otlp/jaeger]
        metrics:
          receivers: [otlp]
          processors: [memory_limiter, batch]
          exporters: [prometheus]

## Span Tag Taxonomy

### Always Present
| Tag | Description |
|-----|-------------|
| agent.id | Fingerprinted agent identifier |
| mcp.method | MCP protocol method |
| mcp.session_id | Session identifier |
| honeypot.phase | research / public |

### Message Spans (protocol layer)
Span name is `mcp.<known method>`, `mcp.unknown_method`, `mcp.response`, `mcp.error`
or `mcp.unknown`; attacker-chosen methods never become span names.

| Tag | Description |
|-----|-------------|
| mcp.message_kind | request / notification / response / error / unknown |
| mcp.method.raw | Method as sent, truncated to 256 characters |
| mcp.jsonrpc.id | JSON-RPC id, truncated |
| mcp.message_size | Serialized size of the message |
| anomaly.flags | Comma-separated protocol flags (see threat-model.md) |
| mcp.client.protocol_version | `initialize` protocolVersion as sent |
| mcp.client.capabilities | Sorted capability keys from `initialize` |
| mcp.client.capabilities_json | Capabilities as JSON, truncated |
| mcp.lifecycle.reason | no_initialize / no_initialized_notification |
| mcp.feature_methods | Feature-list methods seen when feature_enumeration fired |
| mcp.unicode.field_path, mcp.unicode.tag_count, mcp.unicode.decoded, mcp.unicode.other_invisible_count | hidden_unicode details |
| mcp.ansi.field_path, mcp.ansi.sequence_kinds | ansi_escape details |

### Tool Spans
| Tag | Description |
|-----|-------------|
| mcp.tool | Tool name |
| mcp.tool.param_count | Parameter count |
| mcp.tool.params_json | Full params |
| honeypot.response_type | plausible / error / timeout |
| honeypot.response_preview | First 200 chars of response |

### Anomaly Flags
| Flag | Trigger |
|------|---------|
| rapid_enumeration | >10 tool calls in <5s |
| credential_probe | Call to secrets tools |
| privilege_escalation | Tool category shift mid-session |
| param_obfuscation | Base64/encoded params detected |
| replay_attempt | Identical request within 60s |
| path_traversal | ../ in filesystem tool params |
| exfiltration_chain | read-then-network pattern |

## Custom Metrics

    meter = metrics.get_meter("mcp.honeypot")

    tool_call_counter = meter.create_counter(
        "mcp_tool_calls_total",
        description="Total tool calls by tool name and agent"
    )
    anomaly_counter = meter.create_counter(
        "mcp_anomalies_total",
        description="Detected anomalies by flag type"
    )
    response_latency = meter.create_histogram(
        "mcp_response_latency_ms",
        description="Fake response generation latency"
    )
