use anyhow::Result;
use crossterm::{
    cursor,
    event::{self, Event, KeyCode},
    style::{self, Color, Stylize},
    terminal::{self, disable_raw_mode, enable_raw_mode, Clear, ClearType, ScrollUp},
    ExecutableCommand, QueueableCommand,
};
use std::{
    collections::VecDeque,
    io::{self, Write},
    sync::{Arc, Mutex}, // ★追加: スレッド間共有のため
    time::Duration,
};
use tokio::sync::mpsc;
use tokio::time;

const FOOTER_HEIGHT: u16 = 5;

#[tokio::main]
async fn main() -> Result<()> {
    enable_raw_mode()?;
    let mut stdout = io::stdout();
    // stdout.execute(terminal::EnterAlternateScreen)?;
    stdout.execute(ScrollUp(FOOTER_HEIGHT))?;
    stdout.execute(cursor::Hide)?;

    // チャンネル作成
    let (slow_tx, mut slow_rx) = mpsc::channel::<String>(100);
    let (fast_tx, mut fast_rx) = mpsc::channel::<String>(10000); // バッファ多めに

    // ★共有状態: 高速ログのデータ置き場
    // メインスレッド(描画)とバックグラウンドスレッド(受信)で共有する
    let shared_fast_logs = Arc::new(Mutex::new(VecDeque::with_capacity(FOOTER_HEIGHT as usize)));
    
    // 初期データの投入
    {
        let mut logs = shared_fast_logs.lock().unwrap();
        for _ in 0..FOOTER_HEIGHT {
            logs.push_back(String::new());
        }
    }

    // 1. 低速ログ生成タスク
    tokio::spawn(async move {
        let mut count = 0;
        loop {
            time::sleep(Duration::from_secs(1)).await;
            count += 1;
            let _ = slow_tx.send(format!("  [SLOW] System Event Log #{}", count)).await;
        }
    });

    // 2. 高速ログ生成タスク (高負荷シミュレーション: 0.1ms間隔 = 10kHz)
    //    これだけ高速でもUIは固まりません
    tokio::spawn(async move {
        let mut count = 0;
        loop {
            // intervalを使わず全力で回す（高負荷テスト）
            time::sleep(Duration::from_micros(100)).await; 
            count += 1;
            let _ = fast_tx.try_send(format!(">> [FAST] Sensor Data: {} mV", count));
        }
    });

    // ★重要: 高速ログを受信してMutexに書き込む専用タスク
    // これにより、メインループ(select!)は「受信」の責務から解放されます
    let logs_clone = shared_fast_logs.clone();
    tokio::spawn(async move {
        while let Some(msg) = fast_rx.recv().await {
            // ロックを取得してデータを更新
            // この処理は一瞬で終わるのでブロックはほぼ発生しない
            if let Ok(mut logs) = logs_clone.lock() {
                if logs.len() >= FOOTER_HEIGHT as usize {
                    logs.pop_front();
                }
                logs.push_back(msg);
            }
        }
    });

    // 3. メイン UI ループ
    let mut render_interval = time::interval(Duration::from_millis(33)); // 30 FPS
    let mut should_quit = false;

    // 初回描画
    draw_footer(&mut stdout, &shared_fast_logs.lock().unwrap())?;

    loop {
        tokio::select! {
            // A. 低速ログ受信 (頻度が低いのでここに残してOK)
            Some(msg) = slow_rx.recv() => {
                let logs = shared_fast_logs.lock().unwrap();
                print_log_above_footer(&mut stdout, &msg, &logs)?;
            }

            // B. 描画タイミング (33ms毎)
            // 高速ログの受信イベント(fast_rx)はここには書かない！
            _ = render_interval.tick() => {
                let logs = shared_fast_logs.lock().unwrap();
                draw_footer(&mut stdout, &logs)?;
            }

            // C. キー入力チェック
            // タイムアウト付きでpollして、高負荷時でも入力を拾えるようにする
            _ = time::sleep(Duration::from_millis(10)) => {
                // ここでブロックしないようにpollを使用
                if event::poll(Duration::from_millis(0))? {
                    if let Event::Key(key) = event::read()? {
                        if key.code == KeyCode::Char('q') || key.code == KeyCode::Esc {
                            should_quit = true;
                        }
                    }
                }
            }
        }

        if should_quit {
            break;
        }
    }

    let (_, rows) = terminal::size()?;
    stdout.queue(cursor::MoveTo(0, rows))?;
    stdout.queue(style::Print("\n"))?;
    stdout.queue(cursor::Show)?;
    stdout.flush()?;
    
    disable_raw_mode()?;
    Ok(())
}

fn draw_footer(stdout: &mut io::Stdout, logs: &VecDeque<String>) -> Result<()> {
    let (_, rows) = terminal::size()?;
    let start_row = rows.saturating_sub(FOOTER_HEIGHT);

    stdout.queue(cursor::MoveTo(0, start_row))?;
    
    let width = terminal::size()?.0 as usize;
    let separator = "=".repeat(width).blue();
    stdout.queue(style::Print(separator))?;
    stdout.queue(cursor::MoveToNextLine(1))?;

    for (i, log) in logs.iter().enumerate().take((FOOTER_HEIGHT - 1) as usize) {
        stdout.queue(terminal::Clear(ClearType::CurrentLine))?;
        stdout.queue(style::PrintStyledContent(format!("Row {}: {}", i, log).green()))?;
        stdout.queue(cursor::MoveToNextLine(1))?;
    }

    stdout.flush()?;
    Ok(())
}

fn print_log_above_footer(stdout: &mut io::Stdout, msg: &str, footer_logs: &VecDeque<String>) -> Result<()> {
    let (_, rows) = terminal::size()?;
    let footer_start_row = rows.saturating_sub(FOOTER_HEIGHT);

    stdout.queue(ScrollUp(1))?;

    let log_row = footer_start_row.saturating_sub(1);
    stdout.queue(cursor::MoveTo(0, log_row))?;

    stdout.queue(terminal::Clear(ClearType::CurrentLine))?;
    stdout.queue(style::Print(msg))?;

    draw_footer(stdout, footer_logs)?;

    Ok(())
}