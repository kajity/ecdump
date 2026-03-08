use std::collections::VecDeque;
use std::fs::File;
use std::io::BufWriter;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::thread::JoinHandle;
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::BytesMut;
use crossbeam_channel::{Receiver as CbReceiver, Sender as CbSender, TryRecvError};
use crossterm::event::{
    self, DisableMouseCapture, EnableMouseCapture, Event, KeyCode, KeyEventKind, KeyModifiers,
    MouseButton, MouseEventKind,
};
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use crossterm::{execute, terminal};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use ratatui::layout::{Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};
use tokio::runtime::Builder;
use tokio::sync::{mpsc, watch};

use crate::analysis_event::{
    AnalysisEvent, AnalysisEventKind, from_al_status_update, from_ec_error, from_state_transition,
};
use crate::analyzer::DeviceManager;
use crate::packet_source::{self, CapturedData};
use crate::startup::PcapFileConfig;
use ecdump::ec_packet;

const MAX_EVENTS: usize = 10_000;
const UI_EVENT_BUFFER: usize = 4096;

#[derive(Debug, Clone)]
struct PlaybackControl {
    playing: bool,
    step_seq: u64,
    shutdown: bool,
}

#[derive(Debug)]
enum UiEvent {
    Analysis(AnalysisEvent),
    Progress { processed_frames: u64 },
    SourceFinished { total_frames: u64 },
}

#[derive(Debug)]
enum UiCommand {
    Quit,
    TogglePlay,
    Step,
    SelectNext,
    SelectPrev,
    SelectFirst,
    SelectLast,
    SelectAt { col: u16, row: u16 },
    ScrollUp,
    ScrollDown,
    Redraw,
}

pub fn run_interactive_file_mode(
    file: &PcapFileConfig,
    output_file: Option<&str>,
    time_sync: bool,
) -> Result<()> {
    if let Some(path) = output_file
        && path == file.file_path
    {
        anyhow::bail!("Output file path must be different from input file path");
    }

    let file_in = File::open(&file.file_path)
        .with_context(|| format!("Failed to open pcap file: {}", &file.file_path))?;

    let file_out = output_file
        .map(|path| {
            File::create(path)
                .map(BufWriter::new)
                .with_context(|| format!("Failed to create output file: {}", path))
        })
        .transpose()?;

    let (_abort_tx, abort_rx) = crossbeam_channel::bounded::<bool>(0);
    let (source_handle, tx_buffer, rx_data) =
        packet_source::start_read_pcap(file_in, file_out, file.is_pcapng, abort_rx, time_sync)
            .with_context(|| format!("Failed to start reading pcap file: {}", &file.file_path))?;

    let ctrlc_requested = Arc::new(AtomicBool::new(false));
    {
        let ctrlc_requested = Arc::clone(&ctrlc_requested);
        ctrlc::set_handler(move || {
            ctrlc_requested.store(true, Ordering::SeqCst);
        })
        .context("Error setting Ctrl-C handler")?;
    }

    let runtime = Builder::new_multi_thread()
        .enable_all()
        .build()
        .context("Failed to create tokio runtime")?;

    runtime.block_on(run_interactive_async(
        file.file_path.clone(),
        ctrlc_requested,
        source_handle,
        tx_buffer,
        rx_data,
    ))
}

async fn run_interactive_async(
    source_name: String,
    ctrlc_requested: Arc<AtomicBool>,
    source_handle: Option<JoinHandle<()>>,
    tx_buffer: CbSender<BytesMut>,
    rx_data: CbReceiver<CapturedData>,
) -> Result<()> {
    let mut tui = TuiSession::new()?;
    let mut app = InteractiveApp::new(source_name);

    let (ui_event_tx, mut ui_event_rx) = mpsc::channel::<UiEvent>(UI_EVENT_BUFFER);
    let (cmd_tx, mut cmd_rx) = mpsc::unbounded_channel::<UiCommand>();
    let (control_tx, control_rx) = watch::channel(PlaybackControl {
        playing: true,
        step_seq: 0,
        shutdown: false,
    });

    let input_shutdown = Arc::new(AtomicBool::new(false));
    let input_shutdown_task = Arc::clone(&input_shutdown);
    let input_task = tokio::task::spawn_blocking(move || {
        run_input_task(cmd_tx, input_shutdown_task);
    });

    let packet_task = tokio::task::spawn_blocking(move || {
        run_packet_task(rx_data, tx_buffer, control_rx, ui_event_tx);
    });

    let mut control_state = control_tx.borrow().clone();
    app.draw(&mut tui.terminal)?;

    loop {
        if ctrlc_requested.load(Ordering::SeqCst) {
            app.should_quit = true;
        }

        if app.should_quit {
            break;
        }

        tokio::select! {
            cmd = cmd_rx.recv() => {
                match cmd {
                    Some(cmd) => {
                        if apply_ui_command(&mut app, &mut control_state, cmd, &mut tui.terminal)? {
                            break;
                        }
                        let _ = control_tx.send(control_state.clone());
                        app.draw(&mut tui.terminal)?;
                    }
                    None => continue,
                }
            }
            event = ui_event_rx.recv() => {
                match event {
                    Some(event) => {
                        apply_ui_event(&mut app, event);
                        app.draw(&mut tui.terminal)?;
                    }
                    None => break,
                }
            }
            _ = tokio::time::sleep(Duration::from_millis(10)) => {
                // Keep loop responsive to Ctrl-C and shutdown checks.
            }
        }
    }

    control_state.shutdown = true;
    let _ = control_tx.send(control_state);
    input_shutdown.store(true, Ordering::SeqCst);

    let _ = input_task.await;
    let _ = packet_task.await;

    if let Some(handle) = source_handle {
        let _ = handle.join();
    }

    Ok(())
}

fn run_input_task(cmd_tx: mpsc::UnboundedSender<UiCommand>, shutdown: Arc<AtomicBool>) {
    while !shutdown.load(Ordering::SeqCst) {
        match event::poll(Duration::from_millis(20)) {
            Ok(true) => match event::read() {
                Ok(Event::Key(key)) if key.kind == KeyEventKind::Press => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        let _ = cmd_tx.send(UiCommand::Quit);
                        continue;
                    }

                    let cmd = match key.code {
                        KeyCode::Char('q') => Some(UiCommand::Quit),
                        KeyCode::Char(' ') => Some(UiCommand::TogglePlay),
                        KeyCode::Char('n') => Some(UiCommand::Step),
                        KeyCode::Char('j') | KeyCode::Down => Some(UiCommand::SelectNext),
                        KeyCode::Char('k') | KeyCode::Up => Some(UiCommand::SelectPrev),
                        KeyCode::Char('g') => Some(UiCommand::SelectFirst),
                        KeyCode::Char('G') => Some(UiCommand::SelectLast),
                        _ => None,
                    };
                    if let Some(cmd) = cmd {
                        let _ = cmd_tx.send(cmd);
                    }
                }
                Ok(Event::Mouse(mouse)) => {
                    let cmd = match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => Some(UiCommand::SelectAt {
                            col: mouse.column,
                            row: mouse.row,
                        }),
                        MouseEventKind::ScrollUp => Some(UiCommand::ScrollUp),
                        MouseEventKind::ScrollDown => Some(UiCommand::ScrollDown),
                        _ => None,
                    };
                    if let Some(cmd) = cmd {
                        let _ = cmd_tx.send(cmd);
                    }
                }
                Ok(Event::Resize(_, _)) => {
                    let _ = cmd_tx.send(UiCommand::Redraw);
                }
                Ok(_) => {}
                Err(_) => std::thread::sleep(Duration::from_millis(1)),
            },
            Ok(false) => std::thread::sleep(Duration::from_millis(1)),
            Err(_) => std::thread::sleep(Duration::from_millis(5)),
        }
    }
}

fn run_packet_task(
    rx_data: CbReceiver<CapturedData>,
    tx_buffer: CbSender<BytesMut>,
    control_rx: watch::Receiver<PlaybackControl>,
    ui_event_tx: mpsc::Sender<UiEvent>,
) {
    let mut device_manager = DeviceManager::new();
    let mut last_step_seq = 0_u64;

    loop {
        let control = control_rx.borrow().clone();
        if control.shutdown {
            break;
        }

        let stepped = !control.playing && control.step_seq > last_step_seq;
        if !control.playing && !stepped {
            std::thread::sleep(Duration::from_millis(1));
            continue;
        }

        let mut processed_any = false;
        let mut processed_in_this_turn = 0usize;

        while processed_in_this_turn < 256 {
            match rx_data.try_recv() {
                Ok(CapturedData {
                    data: packet,
                    timestamp,
                    from_main,
                }) => {
                    processed_any = true;
                    processed_in_this_turn += 1;

                    let ethercat_packet = match ec_packet::ECFrame::new(packet.as_ref()) {
                        Some(pkt) => pkt,
                        None => continue,
                    };

                    let result =
                        device_manager.analyze_packet(&ethercat_packet, timestamp, from_main);
                    tx_buffer.send(BytesMut::from(packet)).ok();

                    for tr in device_manager.take_state_transitions() {
                        if ui_event_tx
                            .blocking_send(UiEvent::Analysis(from_state_transition(&tr)))
                            .is_err()
                        {
                            return;
                        }
                    }

                    let correlations = device_manager.take_pending_correlations();
                    if let Err(error) = result {
                        for ev in from_ec_error(error, &correlations) {
                            if ui_event_tx.blocking_send(UiEvent::Analysis(ev)).is_err() {
                                return;
                            }
                        }
                    }

                    for update in device_manager.check_al_status_code_updates() {
                        let ev = from_al_status_update(
                            device_manager.get_frame_count(),
                            timestamp,
                            &update,
                        );
                        if ui_event_tx.blocking_send(UiEvent::Analysis(ev)).is_err() {
                            return;
                        }
                    }

                    if stepped {
                        let _ = ui_event_tx.blocking_send(UiEvent::Progress {
                            processed_frames: device_manager.get_frame_count(),
                        });
                        last_step_seq = control.step_seq;
                        break;
                    }

                    if control.playing && device_manager.get_frame_count().is_multiple_of(64) {
                        let _ = ui_event_tx.blocking_send(UiEvent::Progress {
                            processed_frames: device_manager.get_frame_count(),
                        });
                    }
                }
                Err(TryRecvError::Empty) => break,
                Err(TryRecvError::Disconnected) => {
                    let _ = ui_event_tx.blocking_send(UiEvent::SourceFinished {
                        total_frames: device_manager.get_frame_count(),
                    });
                    return;
                }
            }
        }

        if !processed_any {
            std::thread::sleep(Duration::from_millis(1));
        }
    }
}

fn apply_ui_command(
    app: &mut InteractiveApp,
    control: &mut PlaybackControl,
    cmd: UiCommand,
    terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>,
) -> Result<bool> {
    match cmd {
        UiCommand::Quit => {
            app.should_quit = true;
            Ok(true)
        }
        UiCommand::TogglePlay => {
            control.playing = !control.playing;
            app.playing = control.playing;
            Ok(false)
        }
        UiCommand::Step => {
            if !control.playing {
                control.step_seq = control.step_seq.saturating_add(1);
            }
            Ok(false)
        }
        UiCommand::SelectNext | UiCommand::ScrollDown => {
            app.select_next();
            Ok(false)
        }
        UiCommand::SelectPrev | UiCommand::ScrollUp => {
            app.select_prev();
            Ok(false)
        }
        UiCommand::SelectFirst => {
            app.select_first();
            Ok(false)
        }
        UiCommand::SelectLast => {
            app.select_last();
            Ok(false)
        }
        UiCommand::SelectAt { col, row } => {
            let size = terminal.size()?;
            app.select_by_mouse(col, row, Rect::new(0, 0, size.width, size.height));
            Ok(false)
        }
        UiCommand::Redraw => Ok(false),
    }
}

fn apply_ui_event(app: &mut InteractiveApp, event: UiEvent) {
    match event {
        UiEvent::Analysis(event) => app.push_event(event),
        UiEvent::Progress { processed_frames } => {
            app.processed_frames = app.processed_frames.max(processed_frames);
        }
        UiEvent::SourceFinished { total_frames } => {
            app.finished = true;
            app.playing = false;
            app.processed_frames = app.processed_frames.max(total_frames);
            app.total_frames = Some(total_frames);
        }
    }
}

struct InteractiveApp {
    source_name: String,
    events: VecDeque<AnalysisEvent>,
    selected: usize,
    processed_frames: u64,
    total_frames: Option<u64>,
    playing: bool,
    finished: bool,
    should_quit: bool,
    list_scroll: usize,
}

impl InteractiveApp {
    fn new(source_name: String) -> Self {
        Self {
            source_name,
            events: VecDeque::new(),
            selected: 0,
            processed_frames: 0,
            total_frames: None,
            playing: true,
            finished: false,
            should_quit: false,
            list_scroll: 0,
        }
    }

    fn push_event(&mut self, event: AnalysisEvent) {
        self.processed_frames = self.processed_frames.max(event.frame);

        if self.events.len() == MAX_EVENTS {
            self.events.pop_front();
            if self.selected > 0 {
                self.selected -= 1;
            }
        }

        self.events.push_back(event);
        self.selected = self.events.len().saturating_sub(1);
    }

    fn select_next(&mut self) {
        if !self.events.is_empty() {
            self.selected = (self.selected + 1).min(self.events.len() - 1);
        }
    }

    fn select_prev(&mut self) {
        if !self.events.is_empty() {
            self.selected = self.selected.saturating_sub(1);
        }
    }

    fn select_first(&mut self) {
        self.selected = 0;
    }

    fn select_last(&mut self) {
        if !self.events.is_empty() {
            self.selected = self.events.len() - 1;
        }
    }

    fn select_by_mouse(&mut self, col: u16, row: u16, terminal_area: Rect) {
        if self.events.is_empty() {
            return;
        }

        let events_rect = Self::events_rect(terminal_area);
        if col <= events_rect.x
            || row <= events_rect.y
            || col >= events_rect.x + events_rect.width.saturating_sub(1)
            || row >= events_rect.y + events_rect.height.saturating_sub(1)
        {
            return;
        }

        let visible_rows = events_rect.height.saturating_sub(2) as usize;
        if visible_rows == 0 {
            return;
        }

        self.sync_scroll(visible_rows);
        let inner_row = (row - events_rect.y - 1) as usize;
        let idx = self.list_scroll + inner_row;
        if idx < self.events.len() {
            self.selected = idx;
            self.sync_scroll(visible_rows);
        }
    }

    fn sync_scroll(&mut self, visible_rows: usize) {
        if self.events.is_empty() || visible_rows == 0 {
            self.list_scroll = 0;
            return;
        }

        if self.selected < self.list_scroll {
            self.list_scroll = self.selected;
        }
        let last_visible = self.list_scroll + visible_rows.saturating_sub(1);
        if self.selected > last_visible {
            self.list_scroll = self.selected + 1 - visible_rows;
        }

        let max_scroll = self.events.len().saturating_sub(visible_rows);
        if self.list_scroll > max_scroll {
            self.list_scroll = max_scroll;
        }
    }

    fn events_rect(area: Rect) -> Rect {
        let chunks = Layout::default()
            .direction(Direction::Vertical)
            .constraints([
                Constraint::Length(1),
                Constraint::Min(5),
                Constraint::Length(7),
                Constraint::Length(1),
            ])
            .split(area);
        chunks[1]
    }

    fn draw(&mut self, terminal: &mut Terminal<CrosstermBackend<std::io::Stdout>>) -> Result<()> {
        let size = terminal.size()?;
        let area = Rect::new(0, 0, size.width, size.height);
        let visible_rows = Self::events_rect(area).height.saturating_sub(2) as usize;
        self.sync_scroll(visible_rows);

        let start = self.list_scroll;
        let end = (start + visible_rows).min(self.events.len());

        terminal.draw(|frame| {
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(5),
                    Constraint::Length(7),
                    Constraint::Length(1),
                ])
                .split(frame.area());

            let state = if self.finished {
                "Finished"
            } else if self.playing {
                "Playing"
            } else {
                "Paused"
            };
            let total = self
                .total_frames
                .map(|n| n.to_string())
                .unwrap_or_else(|| "?".to_string());

            let header = Paragraph::new(format!(
                "File: {} | State: {} | Frame: {}/{} | Events: {}",
                self.source_name,
                state,
                self.processed_frames,
                total,
                self.events.len()
            ))
            .style(Style::default().add_modifier(Modifier::BOLD));
            frame.render_widget(header, chunks[0]);

            let items: Vec<ListItem<'_>> = self
                .events
                .iter()
                .skip(start)
                .take(end.saturating_sub(start))
                .map(|e| {
                    let prefix = format!(
                        "#{} {:>8.3}s {:<6}",
                        e.frame,
                        e.timestamp.as_secs_f64(),
                        e.title()
                    );
                    let text = format!("{} {}", prefix, e.summary);
                    let style = match e.kind {
                        AnalysisEventKind::FrameError
                        | AnalysisEventKind::Wkc
                        | AnalysisEventKind::Esm => Style::default().fg(Color::Red),
                        AnalysisEventKind::Address => Style::default().fg(Color::Yellow),
                        AnalysisEventKind::State => Style::default().fg(Color::Cyan),
                        AnalysisEventKind::Al => Style::default().fg(Color::Magenta),
                    };
                    ListItem::new(Line::from(text)).style(style)
                })
                .collect();

            let mut state = ratatui::widgets::ListState::default();
            if !self.events.is_empty() {
                state.select(Some(self.selected.saturating_sub(start)));
            }

            let events_list = List::new(items)
                .block(Block::default().title("Events").borders(Borders::ALL))
                .highlight_style(
                    Style::default()
                        .bg(Color::DarkGray)
                        .add_modifier(Modifier::BOLD),
                )
                .highlight_symbol("> ");
            frame.render_stateful_widget(events_list, chunks[1], &mut state);

            let detail_lines = self
                .events
                .get(self.selected)
                .map(|e| {
                    let mut lines = vec![
                        format!("Type: {}", e.title()),
                        format!("Frame: #{}", e.frame),
                        format!("Time: {:.6}s", e.timestamp.as_secs_f64()),
                        String::new(),
                        format!("Summary: {}", e.summary),
                    ];
                    if !e.details.is_empty() {
                        lines.push(String::new());
                        lines.push("Details:".to_string());
                        for d in &e.details {
                            lines.push(format!("- {}", d));
                        }
                    }
                    lines
                })
                .unwrap_or_else(|| vec!["No events yet".to_string()]);

            let detail = Paragraph::new(detail_lines.join("\n"))
                .block(Block::default().title("Detail").borders(Borders::ALL))
                .wrap(Wrap { trim: false });
            frame.render_widget(detail, chunks[2]);

            let footer = Paragraph::new(
                "q: quit | Space: play/pause | n: step | j/k: select | g/G: first/last | mouse: click/wheel",
            )
            .style(Style::default().fg(Color::Gray));
            frame.render_widget(footer, chunks[3]);
        })?;

        Ok(())
    }
}

struct TuiSession {
    terminal: Terminal<CrosstermBackend<std::io::Stdout>>,
}

impl TuiSession {
    fn new() -> Result<Self> {
        enable_raw_mode().context("failed to enable raw mode")?;
        execute!(std::io::stdout(), EnterAlternateScreen, EnableMouseCapture)
            .context("failed to enter alternate screen")?;

        let backend = CrosstermBackend::new(std::io::stdout());
        let terminal = Terminal::new(backend).context("failed to initialize terminal")?;

        Ok(Self { terminal })
    }
}

impl Drop for TuiSession {
    fn drop(&mut self) {
        let _ = disable_raw_mode();
        let _ = execute!(
            self.terminal.backend_mut(),
            LeaveAlternateScreen,
            DisableMouseCapture
        );
        let _ = self.terminal.show_cursor();
        let _ = terminal::disable_raw_mode();
    }
}
