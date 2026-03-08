# Codex実装指示書: インタラクティブUI低遅延化（描画と受信の分離 / Tokio導入）

## 1. 目的
現状のインタラクティブモードで体感遅延が残っているため、以下を満たすように再設計する。

1. `rx_data` 受信は待機時間を挟まず即時処理する。
2. 描画処理と受信・解析処理を完全分離する。
3. UI応答性を保ちながらCPUスピンを抑える。

この文書はCodexが実装を進めるための具体指示書とする。

## 2. 方針（要点）
- 非同期ランタイムとして `tokio` を導入する。
- パイプラインを3系統に分割する。
  - A. Packet Intake/Analyze タスク（受信・解析専任）
  - B. Input タスク（キー/マウスイベント専任）
  - C. Render ループ（描画専任）
- タスク間は `tokio::sync::mpsc` と `watch` で接続する。

## 3. 必要クレート
### 追加
- `tokio`（feature: `rt-multi-thread`, `macros`, `sync`, `time`）
- `tokio-util`（必要なら `sync::CancellationToken` 用）

### 既存利用
- `ratatui`（描画）
- `crossterm`（入力と端末モード制御）
- `crossbeam-channel`（既存 `packet_source` 戻り値受け。段階的移行中は許容）

## 4. 変更対象
- `Cargo.toml`
- `src/main.rs`
- `src/interactive.rs`（大幅改修）
- `src/packet_source.rs`（必要に応じて async API 追加）
- `README.md`（挙動説明更新）

## 5. 目標アーキテクチャ
## 5.1 タスク構成
1. `packet_task`（`tokio::task::spawn_blocking` 推奨）
- `rx_data.try_recv()` をループで吸い切る。
- `DeviceManager` で解析し `AnalysisEvent` を `ui_event_tx` へ送る。
- 1ループで複数パケット処理可（バースト処理）。

2. `input_task`
- `crossterm::event::poll(Duration::from_millis(0))` + `read()`。
- キー/マウスを `UiCommand` として `cmd_tx` へ送る。
- Ctrl-C/`q` は `shutdown` 通知。

3. `render_task`（メインスレッドで実行）
- `tokio::select!` で `cmd_rx`, `ui_event_rx`, `tick` を待つ。
- 状態更新が来たら即描画。
- `tick` は最大FPS制御（例: 60fps上限）にのみ使用。

## 5.2 状態管理
- `InteractiveState` を単一所有（render_task内）にする。
- 他タスクは状態を直接触らない。
- 受信イベントと入力コマンドはメッセージ経由で反映する。

## 6. メッセージ設計
## 6.1 UI向けイベント
- `enum UiEvent`
  - `Analysis(AnalysisEvent)`
  - `SourceFinished { total_frames: u64 }`
  - `SourceError(String)`

## 6.2 入力コマンド
- `enum UiCommand`
  - `Quit`
  - `TogglePlay`
  - `Step`
  - `SelectNext`
  - `SelectPrev`
  - `SelectFirst`
  - `SelectLast`
  - `SelectAt { col: u16, row: u16 }`
  - `ScrollUp`
  - `ScrollDown`

## 7. 遅延対策の具体ルール
1. `packet_task` は `recv_timeout` を使わない。
2. `packet_task` は `try_recv` で空になるまで処理し、空なら短い `sleep(1ms)` か `yield_now`。
3. 描画は「イベント到着時」優先、`tick` は補助。
4. `render_task` はフレームごとに再計算最小化（可視範囲のみList構築）。
5. `ui_event_tx` はバッファ付き（例: 4096）にして一時バースト吸収。

## 8. 実装手順（Codexチェックリスト）
1. `Cargo.toml` に `tokio`（必要なら `tokio-util`）を追加。
2. `main.rs` のインタラクティブ分岐で `interactive::run_interactive_file_mode` を `async` 呼び出しへ変更。
3. `interactive.rs` を以下に再編。
- `run_interactive_file_mode(...) -> Result<()>` 内でTokioランタイム起動。
- `UiEvent` / `UiCommand` 定義追加。
- `packet_task`, `input_task`, `render_loop` 実装。
- 端末初期化/復帰をガードで確実化。
4. 既存のマウス選択処理を `UiCommand::SelectAt` / `ScrollUp/Down` に移植。
5. `packet_source` 側の同期APIで詰まる場合のみ、`async` ラッパを追加。
6. READMEに「低遅延化」「内部処理の非同期化」を追記。
7. `cargo fmt`, `cargo check`, `cargo test` を通す。

## 9. 受け入れ条件
1. イベント到着直後にUIへ反映される（人間の体感で遅延が目立たない）。
2. `rx_data` 受信に固定待機（20ms/5ms等）が存在しない。
3. マウス選択/スクロール、キーボード操作が従来通り動く。
4. `q`/Ctrl-Cで端末が正常復帰する。
5. ファイル終端で `Finished` 状態に遷移し操作不能にならない。

## 10. リスクと回避
- `crossterm` のイベント読取はブロッキング性がある。
  - 対策: `input_task` を専用タスク化しUI本体をブロックしない。
- 描画競合（複数タスクが terminal を触る）。
  - 対策: terminal描画は render_task のみ。
- 既存 `packet_source` は同期スレッド前提。
  - 対策: 段階1は `spawn_blocking` で接続し、段階2で純async化を検討。

## 11. 実施フェーズ（推奨）
1. Phase 1: Tokio導入 + タスク分離（機能互換優先）
2. Phase 2: 受信バースト最適化と描画コスト削減
3. Phase 3: 計測（1秒あたり処理フレーム数、入力応答時間）を追加

## 12. 完了時にCodexが報告すべき内容
1. 追加/変更ファイル一覧
2. 旧ループから除去した待機箇所（該当行）
3. 遅延低減の理由（設計上の根拠）
4. 実行コマンドと結果（fmt/check/test）
