use crate::def::LogLevel;
use arc_swap::{ArcSwap, ArcSwapOption};
use serde::Serialize;
use std::{
    io::{self, IsTerminal, Write},
    sync::{
        Arc, Mutex, OnceLock,
        atomic::{AtomicU64, Ordering},
    },
};
use tokio::sync::broadcast::Sender;
use tracing::level_filters::LevelFilter;
use tracing_log::LogTracer;
#[cfg(target_os = "ios")]
use tracing_oslog::OsLogger;
use tracing_appender::non_blocking::{ErrorCounter, NonBlocking, WorkerGuard};
use tracing_subscriber::{
    EnvFilter, Layer,
    filter::filter_fn,
    fmt::MakeWriter,
    prelude::*,
    registry::Registry,
    reload,
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

pub struct EventCollector(Arc<ArcSwap<Vec<Sender<LogEvent>>>>);

impl EventCollector {
    pub fn new(receivers: Vec<Sender<LogEvent>>) -> Self {
        Self(Arc::new(ArcSwap::from_pointee(receivers)))
    }

    fn take_receivers(&self) -> Arc<Vec<Sender<LogEvent>>> {
        self.0.load_full()
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
        let receivers = self.0.load();
        if receivers.iter().all(|tx| tx.receiver_count() == 0) {
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
        for tx in receivers.iter() {
            if tx.receiver_count() != 0 {
                _ = tx.send(event.clone());
            }
        }
    }
}

#[derive(Clone, Default)]
struct SwapWriter(Arc<ArcSwapOption<NonBlocking>>);

struct OptionalNonBlockingWriter(Option<NonBlocking>);

impl Write for OptionalNonBlockingWriter {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match &mut self.0 {
            Some(writer) => writer.write(buf),
            None => Ok(buf.len()),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match &mut self.0 {
            Some(writer) => writer.flush(),
            None => Ok(()),
        }
    }
}

impl<'a> MakeWriter<'a> for SwapWriter {
    type Writer = OptionalNonBlockingWriter;

    fn make_writer(&'a self) -> Self::Writer {
        OptionalNonBlockingWriter(self.0.load().as_deref().cloned())
    }
}

struct GlobalLogging {
    filter_handle: reload::Handle<EnvFilter, Registry>,
    collector_txs: Arc<ArcSwap<Vec<Sender<LogEvent>>>>,
    file_writer: SwapWriter,
    stdout_writer: SwapWriter,
    active_generation: AtomicU64,
}

impl GlobalLogging {
    fn reconfigure(
        &self,
        filter: EnvFilter,
        collector: EventCollector,
        file_appender: Option<Arc<NonBlocking>>,
        stdout_appender: Arc<NonBlocking>,
    ) -> anyhow::Result<u64> {
        self.filter_handle.reload(filter)?;
        let generation = self.active_generation.fetch_add(1, Ordering::AcqRel) + 1;
        self.collector_txs.store(collector.take_receivers());
        self.file_writer.0.store(file_appender);
        self.stdout_writer.0.store(Some(stdout_appender));
        Ok(generation)
    }

    fn detach(&self, generation: u64) {
        if self.active_generation.load(Ordering::Acquire) == generation {
            self.file_writer.0.store(None);
            self.stdout_writer.0.store(None);
            self.collector_txs.store(Arc::new(Vec::new()));
        }
    }
}

static GLOBAL_LOGGING: OnceLock<Arc<GlobalLogging>> = OnceLock::new();
static LOG_SETUP_LOCK: Mutex<()> = Mutex::new(());
static LOG_TRACER_INIT: OnceLock<()> = OnceLock::new();

#[must_use = "keep the guard alive until the runtime has stopped"]
pub struct LoggingGuard {
    runtime: Option<Arc<GlobalLogging>>,
    generation: u64,
    file_errors: Option<ErrorCounter>,
    stdout_errors: ErrorCounter,
    _file_appender: Option<WorkerGuard>,
    _stdout_appender: WorkerGuard,
}

// RUST_LOG supplies the startup filter. An explicit runtime change replaces it.
pub fn set_log_level(level: LogLevel) -> anyhow::Result<()> {
    if let Some(global) = GLOBAL_LOGGING.get() {
        global.filter_handle.reload(log_filter(level))?;
    }
    Ok(())
}

fn log_filter(level: LogLevel) -> EnvFilter {
    if matches!(level, LogLevel::Silent) {
        EnvFilter::new("off")
    } else {
        EnvFilter::new(format!(
            "warn,clash={level},clash_shadowsocks={level},clash_dns={level},clash_netstack={level}"
        ))
    }
}

pub fn setup_logging(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<LoggingGuard> {
    let guard = setup_logging_inner(level, collector, cwd, log_file)?;
    LOG_TRACER_INIT.get_or_init(|| {
        LogTracer::init().unwrap_or_else(|e| {
            eprintln!("Failed to init tracing-log: {e}");
        });
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
        if let Some(runtime) = &self.runtime {
            let _lock = LOG_SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());
            runtime.detach(self.generation);
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

fn build_logging_subscriber(
    filter: EnvFilter,
    collector: EventCollector,
    file_appender: Option<Arc<NonBlocking>>,
    stdout_appender: Arc<NonBlocking>,
) -> (impl tracing::Subscriber + Send + Sync, Arc<GlobalLogging>) {
    let (filter_layer, filter_handle) = reload::Layer::new(filter);
    let collector_txs = Arc::clone(&collector.0);
    let file_swap = SwapWriter(Arc::new(ArcSwapOption::new(file_appender)));
    let stdout_swap = SwapWriter(Arc::new(ArcSwapOption::new(Some(stdout_appender))));

    let subscriber = tracing_subscriber::registry()
        .with(filter_layer)
        .with(TraceIdLayer);

    let format = time::macros::format_description!(
        "[year repr:last_two]-[month]-[day] [hour]:[minute]:[second].[subsecond digits:3]"
    );

    // 💡 2. 手动创建东八区的 Offset（+8 小时）
    let offset = time::UtcOffset::from_hms(8, 0, 0).unwrap();
    // 💡 这样即使在没有任何时区配置的裸 OpenWrt 固件上运行也绝对不会 Panic
    let timer = tracing_subscriber::fmt::time::OffsetTime::new(offset, format);

    let file_enabled = file_swap.clone();
    let log_to_file_layer = tracing_subscriber::fmt::Layer::new()
        .event_format(TraceIdEventFormatter::new(
            tracing_subscriber::fmt::format()
                .compact()
                .with_timer(timer.clone())
                .with_ansi(false)
                .with_file(true)
                .with_line_number(true)
                .with_level(true),
        ))
        .with_writer(file_swap.clone())
        .with_filter(filter_fn(move |_| file_enabled.0.load().is_some()));

    let stdout_enabled = stdout_swap.clone();
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
        .with_writer(stdout_swap.clone())
        .with_filter(filter_fn(move |_| stdout_enabled.0.load().is_some()));

    let subscriber = subscriber
        .with(collector)
        .with(log_to_file_layer)
        .with(log_stdout_layer);

    #[cfg(target_os = "ios")]
    let subscriber =
        subscriber.with(Some(OsLogger::new("com.watfaq.clash", "default")));

    let runtime = Arc::new(GlobalLogging {
        filter_handle,
        collector_txs,
        file_writer: file_swap,
        stdout_writer: stdout_swap,
        active_generation: AtomicU64::new(1),
    });
    (subscriber, runtime)
}

fn open_file_appender(
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<(Option<Arc<NonBlocking>>, Option<WorkerGuard>)> {
    if let Some(log_file) = log_file {
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
        Ok((Some(Arc::new(non_blocking)), Some(guard)))
    } else {
        Ok((None, None))
    }
}

fn setup_logging_inner(
    level: LogLevel,
    collector: EventCollector,
    cwd: &str,
    log_file: Option<String>,
) -> anyhow::Result<LoggingGuard> {
    let _lock = LOG_SETUP_LOCK.lock().unwrap_or_else(|e| e.into_inner());

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

    let (file_appender, file_guard) = open_file_appender(cwd, log_file)?;
    let file_errors = file_appender.as_ref().map(|writer| writer.error_counter());

    let (stdout_writer, stdout_guard) =
        tracing_appender::non_blocking::NonBlockingBuilder::default()
            .buffered_lines_limit(16_000)
            .lossy(true)
            .thread_name("clash-logger-stdout")
            .finish(std::io::stdout());
    let stdout_errors = stdout_writer.error_counter();
    let stdout_appender = Arc::new(stdout_writer);

    if let Some(global) = GLOBAL_LOGGING.get() {
        let generation =
            global.reconfigure(filter, collector, file_appender, stdout_appender)?;
        return Ok(LoggingGuard {
            runtime: Some(Arc::clone(global)),
            generation,
            file_errors,
            stdout_errors,
            _stdout_appender: stdout_guard,
            _file_appender: file_guard,
        });
    }

    let (subscriber, runtime) =
        build_logging_subscriber(filter, collector, file_appender, stdout_appender);

    if let Err(err) = tracing::subscriber::set_global_default(subscriber) {
        // An embedding host already installed its own global tracing subscriber;
        // do not fail startup when running inside that host process.
        eprintln!("global tracing subscriber already set, reusing host subscriber: {err}");
        return Ok(LoggingGuard {
            runtime: None,
            generation: 0,
            file_errors,
            stdout_errors,
            _stdout_appender: stdout_guard,
            _file_appender: file_guard,
        });
    }

    let _ = GLOBAL_LOGGING.set(Arc::clone(&runtime));

    Ok(LoggingGuard {
        runtime: Some(runtime),
        generation: 1,
        file_errors,
        stdout_errors,
        _stdout_appender: stdout_guard,
        _file_appender: file_guard,
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

    #[test]
    fn setup_logging_supports_repeated_start_stop_cycles() {
        use super::{
            LoggingGuard, build_logging_subscriber, log_filter, open_file_appender,
        };
        use std::{fs, io, sync::Arc};
        use tracing_appender::non_blocking::NonBlockingBuilder;

        let dir = tempdir().unwrap();
        let cwd = dir.path().to_str().unwrap();

        let (file1, file_guard1) =
            open_file_appender(cwd, Some("cycle1.log".to_string())).unwrap();
        let (stdout1, stdout_guard1) =
            NonBlockingBuilder::default().finish(io::sink());
        let (tx1, mut rx1) = broadcast::channel(16);
        let (subscriber, runtime) = build_logging_subscriber(
            log_filter(LogLevel::Info),
            EventCollector::new(vec![tx1]),
            file1,
            Arc::new(stdout1),
        );

        tracing::subscriber::with_default(subscriber, || {
            {
                let _guard1 = LoggingGuard {
                    runtime: Some(Arc::clone(&runtime)),
                    generation: 1,
                    file_errors: None,
                    stdout_errors: stdout_guard1_errors(&runtime),
                    _file_appender: file_guard1,
                    _stdout_appender: stdout_guard1,
                };
                tracing::debug!(target: "clash", "cycle-1-hidden");
                tracing::warn!(target: "clash", "cycle-1-event");
                assert!(rx1.try_recv().unwrap().msg.contains("cycle-1-event"));
                assert!(rx1.try_recv().is_err());
            }

            // Cycle 2 reconfigures the same subscriber with Debug level, new file, and new collector.
            {
                let (file2, file_guard2) =
                    open_file_appender(cwd, Some("cycle2.log".to_string())).unwrap();
                let (stdout2, stdout_guard2) =
                    NonBlockingBuilder::default().finish(io::sink());
                let (tx2, mut rx2) = broadcast::channel(16);
                let gen2 = runtime
                    .reconfigure(
                        log_filter(LogLevel::Debug),
                        EventCollector::new(vec![tx2]),
                        file2,
                        Arc::new(stdout2),
                    )
                    .unwrap();
                let _guard2 = LoggingGuard {
                    runtime: Some(Arc::clone(&runtime)),
                    generation: gen2,
                    file_errors: None,
                    stdout_errors: stdout_guard1_errors(&runtime),
                    _file_appender: file_guard2,
                    _stdout_appender: stdout_guard2,
                };
                tracing::debug!(target: "clash", "cycle-2-debug");
                assert!(rx2.try_recv().unwrap().msg.contains("cycle-2-debug"));
            }
        });

        let log1 = fs::read_to_string(dir.path().join("cycle1.log")).unwrap();
        let log2 = fs::read_to_string(dir.path().join("cycle2.log")).unwrap();
        assert!(log1.contains("cycle-1-event"), "cycle1.log={log1}");
        assert!(!log1.contains("cycle-1-hidden"), "cycle1.log={log1}");
        assert!(log2.contains("cycle-2-debug"), "cycle2.log={log2}");
    }

    fn stdout_guard1_errors(
        runtime: &std::sync::Arc<super::GlobalLogging>,
    ) -> tracing_appender::non_blocking::ErrorCounter {
        runtime
            .stdout_writer
            .0
            .load()
            .as_ref()
            .unwrap()
            .error_counter()
    }
}
