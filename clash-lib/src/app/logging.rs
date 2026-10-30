use crate::def::LogLevel;
use anyhow::anyhow;
#[cfg(feature = "telemetry")]
use opentelemetry::trace::TracerProvider;
#[cfg(feature = "telemetry")]
use opentelemetry_otlp::{Protocol, WithExportConfig};
#[cfg(feature = "telemetry")]
use opentelemetry_semantic_conventions::{
    SCHEMA_URL,
    attribute::{DEPLOYMENT_ENVIRONMENT_NAME, SERVICE_VERSION},
};
use serde::Serialize;
use std::{io::IsTerminal, sync::OnceLock};
use tokio::sync::broadcast::Sender;
use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
#[cfg(feature = "telemetry")]
use tracing_opentelemetry::OpenTelemetryLayer;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_appender::non_blocking::{ErrorCounter, WorkerGuard};
use tracing_subscriber::{
    EnvFilter, Layer, filter::filter_fn, prelude::*, registry::Registry, reload,
};

impl From<LogLevel> for LevelFilter {
    fn from(level: LogLevel) -> Self {
        match level {
            LogLevel::Error => LevelFilter::ERROR,
            LogLevel::Warning => LevelFilter::WARN,
            LogLevel::Info => LevelFilter::INFO,
            LogLevel::Debug => LevelFilter::DEBUG,
            LogLevel::Trace => LevelFilter::TRACE,
            LogLevel::Silent => LevelFilter::OFF,
        }
    }
}

#[derive(Clone, Serialize)]
pub struct LogEvent {
    #[serde(rename = "type")]
    pub level: LogLevel,
    #[serde(rename = "payload")]
    pub msg: String,
}

pub struct TraceIdExtension(pub u64);

struct TraceIdVisitor(Option<u64>);

impl tracing::field::Visit for TraceIdVisitor {
    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        if field.name() == "trace_id" {
            self.0 = Some(value);
        }
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        if field.name() == "trace_id" && value >= 0 {
            self.0 = Some(value as u64);
        }
    }

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "trace_id" {
            let s = format!("{value:?}");
            if let Ok(val) = s.parse::<u64>() {
                self.0 = Some(val);
            }
        }
    }
}

pub struct TraceIdLayer;

impl<S> Layer<S> for TraceIdLayer
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_new_span(
        &self,
        attrs: &tracing::span::Attributes<'_>,
        id: &tracing::span::Id,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = TraceIdVisitor(None);
        attrs.record(&mut visitor);
        if let Some(trace_id) = visitor.0 {
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(TraceIdExtension(trace_id));
            }
        }
    }

    fn on_record(
        &self,
        id: &tracing::span::Id,
        values: &tracing::span::Record<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        let mut visitor = TraceIdVisitor(None);
        values.record(&mut visitor);
        if let Some(trace_id) = visitor.0 {
            if let Some(span) = ctx.span(id) {
                span.extensions_mut().insert(TraceIdExtension(trace_id));
            }
        }
    }
}

pub fn find_trace_id<S>(
    ctx: &tracing_subscriber::layer::Context<'_, S>,
    event: &tracing::Event<'_>,
) -> Option<u64>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    let current = ctx.event_span(event)?;
    for span in current.scope() {
        if let Some(ext) = span.extensions().get::<TraceIdExtension>() {
            return Some(ext.0);
        }
    }
    None
}

use tracing_subscriber::fmt::{
    FmtContext, FormatEvent, FormatFields, format::Writer,
};

#[derive(Default)]
pub struct TraceIdEventFormatter<F = tracing_subscriber::fmt::format::Format> {
    inner: F,
}

impl<F> TraceIdEventFormatter<F> {
    pub fn new(inner: F) -> Self {
        Self { inner }
    }
}

impl<S, N, F> FormatEvent<S, N> for TraceIdEventFormatter<F>
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
    N: for<'a> FormatFields<'a> + 'static,
    F: FormatEvent<S, N>,
{
    fn format_event(
        &self,
        ctx: &FmtContext<'_, S, N>,
        mut writer: Writer<'_>,
        event: &tracing::Event<'_>,
    ) -> std::fmt::Result {
        let mut trace_id = None;
        if let Some(scope) = ctx.event_scope() {
            for span in scope {
                if let Some(ext) = span.extensions().get::<TraceIdExtension>() {
                    trace_id = Some(ext.0);
                    break;
                }
            }
        }

        if let Some(id) = trace_id {
            write!(writer, "[#{id}] ")?;
        }
        self.inner.format_event(ctx, writer, event)
    }
}

pub struct EventCollector(Vec<Sender<LogEvent>>);

impl EventCollector {
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(receivers)
    }
}

impl<S> Layer<S> for EventCollector
where
    S: tracing::Subscriber + for<'a> tracing_subscriber::registry::LookupSpan<'a>,
{
    fn on_event(
        &self,
        event: &tracing::Event<'_>,
        ctx: tracing_subscriber::layer::Context<'_, S>,
    ) {
        if self.0.iter().all(|tx| tx.receiver_count() == 0) {
            return;
        }
        let mut strs = vec![];
        if let Some(trace_id) = find_trace_id(&ctx, event) {
            strs.push(format!("[#{trace_id}]"));
        }
        event.record(&mut EventVisitor(&mut strs));

        let event = LogEvent {
            level: match *event.metadata().level() {
                tracing::Level::ERROR => LogLevel::Error,
                tracing::Level::WARN => LogLevel::Warning,
                tracing::Level::INFO => LogLevel::Info,
                tracing::Level::DEBUG => LogLevel::Debug,
                tracing::Level::TRACE => LogLevel::Trace,
            },
            msg: strs.join(" "),
        };
        for tx in &self.0 {
            if tx.receiver_count() != 0 {
                _ = tx.send(event.clone());
            }
        }
    }
}

#[must_use = "keep the guard alive until the runtime has stopped"]
pub struct LoggingGuard {
    file_errors: Option<ErrorCounter>,
    stdout_errors: ErrorCounter,
    _file_appender: Option<WorkerGuard>,
    _stdout_appender: WorkerGuard,
    #[cfg(feature = "telemetry")]
    _tracing_chrome: Option<tracing_chrome::FlushGuard>,
    #[cfg(feature = "telemetry")]
    _tracer_provider: Option<opentelemetry_sdk::trace::SdkTracerProvider>,
}

static LOG_FILTER: OnceLock<reload::Handle<EnvFilter, Registry>> = OnceLock::new();

// RUST_LOG supplies the startup filter. An explicit runtime change replaces it.
pub fn set_log_level(level: LogLevel) -> anyhow::Result<()> {
    if let Some(handle) = LOG_FILTER.get() {
        handle.reload(log_filter(level))?;
    }
    Ok(())
}

fn log_filter(level: LogLevel) -> EnvFilter {
    let filter = if matches!(level, LogLevel::Silent) {
        EnvFilter::new("off")
    } else {
        EnvFilter::new(format!(
            "warn,clash={level},clash_shadowsocks={level},clash_dns={level},clash_netstack={level}"
        ))
    };
    #[cfg(all(feature = "telemetry", tokio_unstable))]
    let filter = filter
        .add_directive("tokio=trace".parse().unwrap())
        .add_directive("runtime=trace".parse().unwrap());
    filter
}

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<LoggingGuard> {
    let guard = setup_logging_inner(level, collector, cwd, log_file)?;
    LogTracer::init().unwrap_or_else(|e| {
        eprintln!("Failed to init tracing-log: {e}");
    });
    Ok(guard)
}

impl LoggingGuard {
    /// Dropped queue lines for file and stdout, respectively.
    pub fn dropped_lines(&self) -> (usize, usize) {
        (
            self.file_errors.as_ref().map_or(0, |counter| counter.dropped_lines()),
            self.stdout_errors.dropped_lines(),
        )
    }
}

impl Drop for LoggingGuard {
    fn drop(&mut self) {
        #[cfg(feature = "telemetry")]
        if let Some(provider) = self._tracer_provider.take() {
            if let Err(e) = provider.shutdown() {
                eprintln!("Failed to shut down telemetry: {e}");
            }
        }
        let (file_dropped, stdout_dropped) = self.dropped_lines();
        if file_dropped != 0 || stdout_dropped != 0 {
            eprintln!(
                "Logging queue dropped lines: file={file_dropped}, stdout={stdout_dropped}"
            );
        }
        // Worker guards drain their queues when the owning runtime returns.
    }
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<LoggingGuard> {
    let default_log_level = log_filter(level);
    let filter = EnvFilter::try_from_default_env()
        .inspect(|f| {
            eprintln!("using env log level: {f}");
        })
        .inspect_err(|_| {
            if let Ok(log_level) = std::env::var("RUST_LOG") {
                eprintln!("Failed to parse log level from environment: {log_level}");
                eprintln!("Using default log level: {default_log_level}");
            }
        })
        .unwrap_or(default_log_level);

    let (appender, guard) = if let Some(log_file) = log_file {
        let path_buf = std::path::PathBuf::from(&log_file);
        let log_path = if path_buf.is_absolute() {
            log_file
        } else {
            format!("{cwd}/{log_file}")
        };
        let writer: std::fs::File = std::fs::File::options()
            .create(true)
            .append(true)
            .open(log_path)?;
        let (non_blocking, guard) =
            tracing_appender::non_blocking::NonBlockingBuilder::default()
                .buffered_lines_limit(16_000)
                .lossy(true)
                .thread_name("clash-logger-appender")
                .finish(writer);
        (Some(non_blocking), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let (tracing_chrome, tracing_chrome_g) = if cfg!(feature = "telemetry") {
        let builder = tracing_chrome::ChromeLayerBuilder::new();
        let (layer, guard) = builder.build();
        (Some(layer), Some(guard))
    } else {
        (None, None)
    };

    #[cfg(feature = "telemetry")]
    let exporter = opentelemetry_otlp::SpanExporter::builder()
        .with_http()
        .with_protocol(Protocol::HttpBinary)
        .build()?;

    #[cfg(feature = "telemetry")]
    let tracer_provider = opentelemetry_sdk::trace::SdkTracerProvider::builder()
        // Customize sampling strategy
        .with_sampler(opentelemetry_sdk::trace::Sampler::ParentBased(Box::new(opentelemetry_sdk::trace::Sampler::TraceIdRatioBased(
            if cfg!(debug_assertions) {
                1.0 // 100% sampling in development
            } else {
                0.1 // 10% sampling in production
            },
        ))))
        .with_id_generator(opentelemetry_sdk::trace::RandomIdGenerator::default())
        .with_resource(opentelemetry_sdk::Resource::builder()
            .with_service_name(env!("CARGO_PKG_NAME"))
            .with_schema_url(
                [
                    opentelemetry::KeyValue::new(SERVICE_VERSION, env!("CARGO_PKG_VERSION")),
                    opentelemetry::KeyValue::new(DEPLOYMENT_ENVIRONMENT_NAME,  if cfg!(debug_assertions) {
                        "development"
                    } else {
                        "production"
                    }),
            ],
            SCHEMA_URL,
        )
        .build())
        .with_batch_exporter(exporter)
        .build();
    #[cfg(feature = "telemetry")]
    let tracer = tracer_provider.tracer("tracing-otel-subscriber");

    #[cfg(all(feature = "telemetry", tokio_unstable))]
    let filter = filter
        .add_directive("tokio=trace".parse().unwrap())
        .add_directive("runtime=trace".parse().unwrap());
    let (filter, filter_handle) = reload::Layer::new(filter);
    let subscriber = tracing_subscriber::registry().with(filter).with(TraceIdLayer);

    // Collect and expose data about the Tokio runtime (tasks, threads, resources,
    // etc.) — gated on tokio_unstable because console_subscriber panics at
    // runtime if Tokio was compiled without --cfg tokio_unstable. When tests
    // are run with RUSTFLAGS="--cfg docker_test", that env-var overrides
    // .cargo/config.toml, so tokio_unstable is absent and the gate correctly
    // excludes this code.
    #[cfg(all(feature = "telemetry", tokio_unstable))]
    let subscriber = subscriber.with(console_subscriber::spawn());
    let exclude = filter_fn(|metadata| {
        #[cfg(all(feature = "telemetry", tokio_unstable))]
        {
            !metadata.target().contains("tokio")
                && !metadata.target().contains("runtime")
        }
        #[cfg(not(all(feature = "telemetry", tokio_unstable)))]
        {
            let _ = metadata;
            true
        }
    });

    let format = time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
    );

    // 💡 2. 手动创建东八区的 Offset（+8 小时）
    let offset = time::UtcOffset::from_hms(8, 0, 0).unwrap();
    // 💡 这样即使在没有任何时区配置的裸 OpenWrt 固件上运行也绝对不会 Panic
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(offset, format);

    let file_errors = appender.as_ref().map(|writer| writer.error_counter());
    let log_to_file_layer = appender.map(|x| {
        tracing_subscriber::fmt::Layer::new()
            .event_format(TraceIdEventFormatter::new(
                tracing_subscriber::fmt::format()
                    .compact()
                    .with_timer(timer.clone())
                    .with_ansi(false)
                    .with_file(true)
                    .with_line_number(true)
                    .with_level(true),
            ))
            .with_writer(x)
            .with_filter(exclude.clone())
    });
    let (stdout_writer, stdout_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(16_000)
            .lossy(true)
            .thread_name("clash-logger-stdout")
            .finish(std::io::stdout());
    let stdout_errors = stdout_writer.error_counter();
    let log_stdout_layer = tracing_subscriber::fmt::Layer::new()
        .event_format(TraceIdEventFormatter::new(
            tracing_subscriber::fmt::format()
                .compact()
                .with_timer(timer)
                .with_ansi(std::io::stdout().is_terminal())
                .with_target(cfg!(debug_assertions))
                .with_file(true)
                .with_line_number(true)
                .with_level(true)
                .with_thread_ids(cfg!(debug_assertions)),
        ))
        .with_writer(stdout_writer)
        .with_filter(exclude.clone());

    let subscriber = {
        #[cfg(feature = "telemetry")]
        {
            subscriber
        .with(tracing_chrome)
        .with(OpenTelemetryLayer::new(tracer))
        .with(collector.with_filter(exclude.clone()))
        .with(log_to_file_layer)
        .with(log_stdout_layer)
        }
        #[cfg(not(feature = "telemetry"))]
        {
            subscriber
        .with(collector.with_filter(exclude.clone()))
        .with(log_to_file_layer)
        .with(log_stdout_layer)
        }
    };

    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    tracing::subscriber::set_global_default(subscriber)
        .map_err(|x| anyhow!("setup logging error: {}", x))?;

    let _ = LOG_FILTER.set(filter_handle);

    Ok(LoggingGuard {
        file_errors,
        stdout_errors,
        _stdout_appender: stdout_guard,
        _file_appender: guard,
        #[cfg(feature = "telemetry")]
        _tracing_chrome: tracing_chrome_g,
        #[cfg(feature = "telemetry")]
        _tracer_provider: Some(tracer_provider),
    })
}

struct EventVisitor<'a>(&'a mut Vec<String>);

impl EventVisitor<'_> {
    fn push_display(
        &mut self,
        field: &tracing::field::Field,
        value: impl std::fmt::Display,
    ) {
        if field.name() == "message" {
            self.0.push(value.to_string());
        } else {
            self.0.push(format!("{}={}", field.name(), value));
        }
    }

    fn push_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        if field.name() == "message" {
            self.0.push(format!("{value:?}"));
        } else {
            self.0.push(format!("{}={value:?}", field.name()));
        }
    }
}

impl tracing::field::Visit for EventVisitor<'_> {
    fn record_f64(&mut self, field: &tracing::field::Field, value: f64) {
        self.push_display(field, value);
    }

    fn record_i64(&mut self, field: &tracing::field::Field, value: i64) {
        self.push_display(field, value);
    }

    fn record_u64(&mut self, field: &tracing::field::Field, value: u64) {
        self.push_display(field, value);
    }

    fn record_i128(&mut self, field: &tracing::field::Field, value: i128) {
        self.push_display(field, value);
    }

    fn record_u128(&mut self, field: &tracing::field::Field, value: u128) {
        self.push_display(field, value);
    }

    fn record_bool(&mut self, field: &tracing::field::Field, value: bool) {
        self.push_display(field, value);
    }

    fn record_str(&mut self, field: &tracing::field::Field, value: &str) {
        self.push_display(field, value);
    }

    fn record_error(
        &mut self,
        field: &tracing::field::Field,
        value: &(dyn std::error::Error + 'static),
    ) {
        self.push_display(field, value);
    }

    fn record_debug(
        &mut self,
        field: &tracing::field::Field,
        value: &dyn std::fmt::Debug,
    ) {
        self.push_debug(field, value);
    }
}

#[cfg(test)]
mod tests {
    use super::{EventCollector, LogLevel};
    use tempfile::tempdir;
    use tokio::sync::broadcast;
    use tracing_subscriber::{layer::SubscriberExt, registry};

    #[test]
    fn ebpf_startup_event_gate_matches_configured_log_level() {
        use super::log_filter;
        use tracing::{Level, enabled};

        for (level, expected) in [
            (LogLevel::Silent, false), (LogLevel::Error, false),
            (LogLevel::Warning, false), (LogLevel::Info, false),
            (LogLevel::Debug, true), (LogLevel::Trace, true),
        ] {
            let (tx, mut rx) = broadcast::channel(4);
            let subscriber = registry().with(log_filter(level))
                .with(EventCollector::new(vec![tx]));
            tracing::subscriber::with_default(subscriber, || {
                // Same target and level as the BPF manager's startup check.
                assert_eq!(enabled!(target: "clash-ebpf", Level::DEBUG), expected);
                tracing::debug!(target: "clash-ebpf", "redirected");
            });
            assert_eq!(rx.try_recv().is_ok(), expected);
        }
    }

    #[test]
    fn ebpf_startup_event_gate_respects_rust_log_target_overrides() {
        use super::EnvFilter;
        use tracing::{Level, enabled};

        // Parse startup RUST_LOG directives without mutating process-wide env.
        for (directives, expected) in [
            ("info", false), ("debug", true), ("trace", true),
            ("info,clash-ebpf=debug", true),
            ("trace,clash-ebpf=info", false),
            ("debug,clash-ebpf=off", false),
            ("info,clash_lib=debug", false),
        ] {
            let (tx, mut rx) = broadcast::channel(4);
            let subscriber = registry().with(EnvFilter::try_new(directives).unwrap())
                .with(EventCollector::new(vec![tx]));
            tracing::subscriber::with_default(subscriber, || {
                assert_eq!(enabled!(target: "clash-ebpf", Level::DEBUG), expected, "{directives}");
                tracing::debug!(target: "clash-ebpf", "redirected");
            });
            assert_eq!(rx.try_recv().is_ok(), expected, "{directives}");
        }
    }

    #[test]
    fn debug_connection_span_is_only_retained_at_debug_level() {
        use super::{TraceIdLayer, log_filter, reload};
        let (tx, mut rx) = broadcast::channel(4);
        let (filter, handle) = reload::Layer::new(log_filter(LogLevel::Info));
        let subscriber = registry().with(filter).with(TraceIdLayer)
            .with(EventCollector::new(vec![tx]));
        tracing::subscriber::with_default(subscriber, || {
            {
                let span = tracing::debug_span!("connection", trace_id = 11u64);
                let _entered = span.enter();
                tracing::warn!("info mode");
            }
            handle.reload(log_filter(LogLevel::Debug)).unwrap();
            let span = tracing::debug_span!("connection", trace_id = 11u64);
            let _entered = span.enter();
            tracing::warn!("debug mode");
        });
        assert_eq!(rx.try_recv().unwrap().msg, "info mode");
        assert_eq!(rx.try_recv().unwrap().msg, "[#11] debug mode");
    }

    #[test]
    fn file_open_failure_is_reported_before_subscriber_installation() {
        use super::setup_logging_inner;
        let directory = tempdir().unwrap();
        let result = setup_logging_inner(
            LogLevel::Info, EventCollector::new(vec![]),
            directory.path().to_str().unwrap(), Some("missing/log.txt".into()),
        );
        assert!(result.is_err());
    }

    #[test]
    fn runtime_filter_changes_enabled_events() {
        use super::{log_filter, reload};
        let (tx, mut rx) = broadcast::channel(4);
        let (filter, handle) = reload::Layer::new(log_filter(LogLevel::Info));
        let subscriber = registry().with(filter).with(EventCollector::new(vec![tx]));
        tracing::subscriber::with_default(subscriber, || {
            tracing::debug!("hidden");
            tracing::debug!(target: "clash_shadowsocks::relay", "ss hidden");
            handle.reload(log_filter(LogLevel::Debug)).unwrap();
            tracing::debug!("visible");
            tracing::debug!(target: "clash_shadowsocks::relay", "ss visible");
            handle.reload(log_filter(LogLevel::Silent)).unwrap();
            tracing::error!("hidden too");
            tracing::error!(target: "clash_shadowsocks::relay", "ss silent");
        });
        assert_eq!(rx.try_recv().unwrap().msg, "visible");
        assert_eq!(rx.try_recv().unwrap().msg, "ss visible");
        assert!(rx.try_recv().is_err());
    }

    #[test]
    fn formatter_and_collector_use_explicit_event_parent() {
        use super::{TraceIdEventFormatter, TraceIdLayer};
        use std::sync::{Arc, Mutex};
        use std::io::{self, Write};

        #[derive(Clone)]
        struct Buffer(Arc<Mutex<Vec<u8>>>);
        impl Write for Buffer {
            fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }
            fn flush(&mut self) -> io::Result<()> {
                Ok(())
            }
        }
        let output = Buffer(Arc::new(Mutex::new(Vec::new())));
        let writer = output.clone();
        let (tx, mut rx) = broadcast::channel(4);
        let fmt = tracing_subscriber::fmt::layer()
            .event_format(TraceIdEventFormatter::new(
                tracing_subscriber::fmt::format().without_time().with_ansi(false),
            ))
            .with_writer(move || writer.clone());
        let subscriber = registry().with(TraceIdLayer)
            .with(EventCollector::new(vec![tx])).with(fmt);
        tracing::subscriber::with_default(subscriber, || {
            let parent = tracing::info_span!("parent", trace_id = 11u64);
            let current = tracing::info_span!("current", trace_id = 22u64);
            let _entered = current.enter();
            tracing::info!(parent: &parent, "explicit");
            tracing::info!(parent: None, "root");
        });
        assert!(rx.try_recv().unwrap().msg.starts_with("[#11]"));
        assert_eq!(rx.try_recv().unwrap().msg, "root");
        let bytes = output.0.lock().unwrap();
        let text = std::str::from_utf8(&bytes).unwrap();
        let mut lines = text.lines();
        assert!(lines.next().unwrap().starts_with("[#11]"));
        assert!(!lines.next().unwrap().starts_with("[#"));
    }

    #[test]
    fn collector_keeps_message_and_fields_inline() {
        let (tx, mut rx) = broadcast::channel(1);
        let collector = EventCollector::new(vec![tx]);
        let subscriber = registry().with(collector);

        tracing::subscriber::with_default(subscriber, || {
            tracing::info!(answer = 42u64, kind = "demo", success = true, "hello");
        });

        let event = rx.try_recv().expect("expected collected log event");

        assert!(matches!(event.level, LogLevel::Info));
        assert!(event.msg.contains("hello"));
        assert!(event.msg.contains("answer=42"));
        assert!(event.msg.contains("kind=demo"));
        assert!(event.msg.contains("success=true"));
    }

    #[test]
    fn collector_automatically_includes_trace_id() {
        use super::TraceIdLayer;

        let (tx, mut rx) = broadcast::channel(1);
        let collector = EventCollector::new(vec![tx]);
        let subscriber = registry().with(TraceIdLayer).with(collector);

        tracing::subscriber::with_default(subscriber, || {
            let span = tracing::info_span!("request", trace_id = 10000000u64);
            let _guard = span.enter();
            tracing::info!("inner request log message");
        });

        let event = rx.try_recv().expect("expected collected log event");

        assert!(matches!(event.level, LogLevel::Info));
        assert!(event.msg.contains("[#10000000]"));
        assert!(event.msg.contains("inner request log message"));
    }
}
