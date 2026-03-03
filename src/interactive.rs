use std::collections::VecDeque;
use std::fs::File;
use std::io::BufWriter;
use std::sync::{
    Arc,
    atomic::{AtomicBool, Ordering},
};
use std::time::Duration;

use anyhow::{Context, Result};
use bytes::BytesMut;
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
use ratatui::layout::Rect;
use ratatui::layout::{Constraint, Direction, Layout};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::Line;
use ratatui::widgets::{Block, Borders, List, ListItem, Paragraph, Wrap};

use crate::analysis_event::{
    AnalysisEvent, AnalysisEventKind, from_al_status_update, from_ec_error, from_state_transition,
};
use crate::analyzer::DeviceManager;
use crate::packet_source::{self, CapturedData};
use crate::startup::PcapFileConfig;
use ecdump::ec_packet;

const MAX_EVENTS: usize = 10_000;

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
    let (handle, tx_buffer, rx_data) =
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

    let mut tui = TuiSession::new()?;
    let mut app = InteractiveApp::new(file.file_path.clone());
    let mut device_manager = DeviceManager::new();
    let mut needs_redraw = true;

    loop {
        if ctrlc_requested.load(Ordering::SeqCst) || app.should_quit {
            break;
        }

        let mut progressed = false;

        let should_process_packet = !app.finished && (app.playing || app.step_requested);
        if should_process_packet {
            match rx_data.try_recv() {
                Ok(CapturedData {
                    data: packet,
                    timestamp,
                    from_main,
                }) => {
                    app.step_requested = false;
                    progressed = true;

                    let ethercat_packet = match ec_packet::ECFrame::new(packet.as_ref()) {
                        Some(pkt) => pkt,
                        None => {
                            continue;
                        }
                    };

                    let result =
                        device_manager.analyze_packet(&ethercat_packet, timestamp, from_main);
                    app.processed_frames = device_manager.get_frame_count();

                    tx_buffer.send(BytesMut::from(packet)).ok();

                    let transitions = device_manager.take_state_transitions();
                    for tr in transitions {
                        app.push_event(from_state_transition(&tr));
                    }

                    let correlations = device_manager.take_pending_correlations();
                    if let Err(error) = result {
                        for event in from_ec_error(error, &correlations) {
                            app.push_event(event);
                        }
                    }

                    let al_updates = device_manager.check_al_status_code_updates();
                    for update in al_updates {
                        app.push_event(from_al_status_update(
                            app.processed_frames,
                            timestamp,
                            &update,
                        ));
                    }
                }
                Err(crossbeam_channel::TryRecvError::Empty) => {}
                Err(crossbeam_channel::TryRecvError::Disconnected) => {
                    app.finished = true;
                    app.total_frames = Some(app.processed_frames);
                    progressed = true;
                }
            }
        }

        if event::poll(Duration::from_millis(0))? {
            match event::read()? {
                Event::Key(key) if key.kind == KeyEventKind::Press => {
                    if key.modifiers.contains(KeyModifiers::CONTROL)
                        && key.code == KeyCode::Char('c')
                    {
                        break;
                    }

                    match key.code {
                        KeyCode::Char('q') => app.should_quit = true,
                        KeyCode::Char(' ') => app.playing = !app.playing,
                        KeyCode::Char('n') => {
                            if !app.playing {
                                app.step_requested = true;
                            }
                        }
                        KeyCode::Char('j') | KeyCode::Down => app.select_next(),
                        KeyCode::Char('k') | KeyCode::Up => app.select_prev(),
                        KeyCode::Char('g') => app.select_first(),
                        KeyCode::Char('G') => app.select_last(),
                        _ => {}
                    }
                    progressed = true;
                }
                Event::Mouse(mouse) => {
                    match mouse.kind {
                        MouseEventKind::Down(MouseButton::Left) => {
                            let size = tui.terminal.size()?;
                            app.select_by_mouse(
                                mouse.column,
                                mouse.row,
                                Rect::new(0, 0, size.width, size.height),
                            );
                        }
                        MouseEventKind::ScrollDown => app.select_next(),
                        MouseEventKind::ScrollUp => app.select_prev(),
                        _ => {}
                    }
                    progressed = true;
                }
                Event::Resize(_, _) => progressed = true,
                _ => {}
            }
        }

        if needs_redraw || progressed {
            app.draw(&mut tui.terminal)?;
            needs_redraw = false;
        }

        if !progressed {
            std::thread::sleep(Duration::from_millis(1));
        }
    }

    drop(rx_data);
    drop(tx_buffer);

    if let Some(handle) = handle {
        let _ = handle.join();
    }

    Ok(())
}

struct InteractiveApp {
    source_name: String,
    events: VecDeque<AnalysisEvent>,
    selected: usize,
    processed_frames: u64,
    total_frames: Option<u64>,
    playing: bool,
    step_requested: bool,
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
            step_requested: false,
            finished: false,
            should_quit: false,
            list_scroll: 0,
        }
    }

    fn push_event(&mut self, event: AnalysisEvent) {
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
            let area = frame.area();
            let chunks = Layout::default()
                .direction(Direction::Vertical)
                .constraints([
                    Constraint::Length(1),
                    Constraint::Min(5),
                    Constraint::Length(7),
                    Constraint::Length(1),
                ])
                .split(area);

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
