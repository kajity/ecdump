# Codex実装指示書: ファイル解析モードのインタラクティブUI対応

## 1. 目的
`ecdump` の **ファイル解析モード（`--file`）** で、ユーザーが解析再生を操作できるインタラクティブUIを実装する。

この指示書は、Codexがそのまま実装を進めるためのタスク分解・設計方針・受け入れ条件を定義する。

## 2. スコープ
### 対象
- `--file` 実行時のインタラクティブ表示とキー操作
- 解析イベント（エラー/状態遷移/相関）の時系列表示
- 再生制御（再生/一時停止/ステップ）
- 終了時サマリ表示

### 非対象（今回やらない）
- ライブキャプチャ（`--interface`）でのインタラクティブUI
- マウス操作
- 複雑なクエリ言語や永続設定ファイル

## 3. 必要クレート
### 追加
- `ratatui`（TUIレイアウト/描画）

### 既存利用
- `crossterm`（入力イベント/Raw mode/Alternate screen）
- `crossbeam-channel`（既存スレッド間連携）
- `anyhow`（エラーハンドリング）

## 4. CLI/モード仕様
1. `startup::Config` に `interactive: bool` を追加する。
2. `-I, --interactive` は **`--file` 指定時のみ有効** にする。
3. `--interactive` と `--interface` の同時利用は `clap` エラーで終了する。
4. 既存の非インタラクティブ挙動は維持する（デフォルト互換）。

## 5. UI仕様（v1）
### 画面構成
1. Header: 入力ファイル名、再生状態、現在フレーム/総フレーム
2. Main Pane: 解析イベントの時系列リスト（新しいものを下）
3. Side/Bottom Pane: 選択イベント詳細（原因、サブデバイス、WKC/ESM情報）
4. Footer: キーバインドヘルプ

### キーバインド
- `q`: 終了
- `Space`: 再生/一時停止
- `n`: 1フレーム進める（停止中のみ）
- `j` / `k`: イベント選択移動
- `g` / `G`: 先頭/末尾へ移動

## 6. 実装アーキテクチャ
### 新規モジュール
- `src/interactive.rs`
  - `InteractiveApp`（状態管理）
  - `run_interactive_file_mode(...) -> anyhow::Result<()>`
  - 入力イベント処理（crossterm）
  - 描画処理（ratatui）

- `src/analysis_event.rs`
  - `enum AnalysisEvent`（UI描画用の正規化イベント）
  - 既存の `ECError` / `StateTransition` / `AlStatusCodeUpdate` からの変換関数

### 既存モジュール変更
- `src/startup.rs`
  - `Config` に `interactive` を追加
  - 引数バリデーション追加

- `src/main.rs`
  - `PcapSource::File` かつ `interactive == true` の場合に `interactive::run_interactive_file_mode` を呼ぶ分岐を追加
  - 既存ループは非インタラクティブ経路として維持

- `src/error_formatter.rs`
  - 既存利用は維持
  - 可能なら UI用の文言生成ロジックを再利用できるよう関数を公開/共通化（必要最小限）

## 7. データフロー（v1）
1. ファイル読み込みは既存 `packet_source::start_read_pcap` を利用。
2. メイン解析ループで `DeviceManager` により解析。
3. 解析結果を `AnalysisEvent` に変換し、`InteractiveApp.events` に蓄積。
4. 再生状態に応じて:
   - 再生中: 新規フレームを継続処理
   - 停止中: 入力待ち（`n` のときのみ1フレーム処理）
5. 各ループでUI再描画。

## 8. 実装手順（Codex用チェックリスト）
1. `Cargo.toml` に `ratatui` を追加する。
2. `startup::Config` へ `interactive` を追加し、`parse_args` の整合を取る。
3. `src/analysis_event.rs` を作成し、UI向けイベント型を定義する。
4. `src/interactive.rs` を作成し、以下を実装する。
   - 端末初期化/復帰（Raw mode, alternate screen）
   - 入力処理ループ
   - 画面描画
   - 再生制御ロジック
5. `src/main.rs` からインタラクティブ経路を呼び出す。
6. READMEに `--interactive` の使い方とキーバインドを追記する。
7. `cargo fmt` / `cargo clippy` / `cargo test` を実行し、失敗時は修正する。

## 9. 受け入れ条件
1. `ecdump -f sample.pcap -I` でUIが起動する。
2. `q` で端末表示が壊れず正常終了する。
3. `Space` と `n` で解析進行を制御できる。
4. エラーイベントと状態遷移イベントがUI上で確認できる。
5. `ecdump -i eth0 -I` は引数エラーになる。
6. `-I` なしの既存実行結果が従来どおりである。

## 10. 実装上の注意
- panic時も端末を復帰できるよう、終了処理を `Drop` ガードで実装する。
- 描画負荷を避けるため、再描画は入力または新規イベント到着時中心に行う。
- イベント蓄積は上限を持たせる（例: 最新10,000件）ことでメモリ増大を抑える。
- 既存のログ出力とTUI出力が干渉しないよう、インタラクティブ時は標準出力ログを抑制する。

## 11. 将来拡張（メモ）
- フィルタ（`WKCのみ`, `ESMのみ`, `subdevice指定`）
- 検索（正規表現）
- ジャンプ（フレーム番号/時刻）
- ライブモード対応
