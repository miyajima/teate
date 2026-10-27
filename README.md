# Teate — てあて

An open-source CLI for tracking vulnerabilities across Macs, source repositories
and cloud workloads, preparing narrow dependency patches, and verifying fixes.
Python 3.11+ and Git are required; the core has no Python runtime dependencies.
Licensed under [MIT](LICENSE). See [SECURITY.md](SECURITY.md) and
[CONTRIBUTING.md](CONTRIBUTING.md).

```bash
git clone https://github.com/miyajima/teate.git
cd teate
python3 -m teate init --root /path/to/projects --output config/local.json
python3 -m teate agent cycle --scanner npm-audit --prepare
python3 -m teate agent render
```

`npm-audit` requires npm and checks npm lockfiles only. Use OSV-Scanner for broader
coverage. Unsupported, failed or stale checks remain unknown. Operational data
stays local by default. Store shared ledgers and reports in a **separate private
repository**; a branch of this public repository is public too. Operational GitHub
Actions are disabled in public repositories and require explicit opt-in in a
private operations repository. The public CI runs synthetic unit tests only.

Macとクラウドの脆弱性対応を、検出から修正・反映・解消確認までつなぎます。

Teate v0.4はPython 3.11以降のCLIです。Python実行時の外部ライブラリは不要です。SQLiteの台帳、JSONの検査証跡、GitHub Issuesによる対応管理、隔離した修正候補の作成、Renovateによる修正PR、GitHub Actionsの実行フローを備えます。

**中核処理はLLM不要です。** 検出・優先度・対応期限・マージ可否・解消確認はコードが決めます。LLMを呼び出し側に置く場合は、luna/maxを想定した短いJSON窓口を使います。通常処理はLLM呼び出し0回です。`cycle --llm codex`を明示した場合だけ、残った例外をChatGPT認証済みのCodex CLIで最大1件調査できます。APIキーへの切替はありません。モデルの応答がなくても、壊れていても定型レポートを生成できます。

```bash
python3 -m teate agent cycle --scanner osv --prepare
python3 -m teate agent render
```

`cycle`が情報更新・検査・台帳更新・レポート作成をまとめて実行し、12KB以内のJSONを返します。OSV通信が制限された環境では`--scanner npm-audit`を使い、対象外を未確認として残します。状態の参照だけなら`agent brief`を使います。[小型モデル向けの契約と検証範囲](docs/small-model.md)を参照してください。

ソースコードは公開して利用・改変できます。個人の台帳・資産一覧・認証・検査結果は含めず、利用者ごとに作成します。`config/ci.json`の管理対象は初期状態で空です。CI設定例は[config/ci.example.json](config/ci.example.json)を使い、実データは非公開の運用リポジトリに置いてください。[導入チェックリスト](docs/handoff.md)も参照してください。

## 動かす

```bash
python3 -m teate init --root /path/to/projects --output config/local.json
python3 scripts/install_scanners.py --directory .teate/bin
export PATH="$PWD/.teate/bin:$PATH"
python3 -m teate refresh-feeds
python3 -m teate run
python3 -m teate report
```

OSV APIに接続できない環境では、npmのlockfileに限り、以下の検査も利用できます。Rust等の対象外manifestは「未検査」として残ります。

```bash
python3 -m teate run --scanner npm-audit
python3 -m teate plan
```

`run` / `scan` の終了コードは、0=取得した検査が完全に成功、1=未対応・部分検査・取得失敗あり、2=設定・同期等のエラーです。0は「脆弱性がゼロ」を意味しません。指摘件数は`status`または`report`を確認してください。

## 何を管理するか

- **source**: プロジェクトのlockfile。GitHub main、Macのcheckout、クラウド作業領域を別資産として登録します。
- **image**: SHA256で固定したイメージ。Trivyが返した実体digestと照合します。
- **cloud-run**: トラフィックを受けるrevisionに加え、タグで到達可能なrevisionの全イメージを検査します。`gcloud`の設定済み読み取り権限と`trivy`が必要です。
- **mac**: macOSとHomebrewのインストール情報。v0.1のMac本体・ブラウザーについては、CVEとの自動照合は未実装です。棚卸し結果を安全確認とは扱いません。

設定例は[config/example.json](config/example.json)。共有ルールは[config/policy.json](config/policy.json)です。Macとクラウドで同じCVEが見つかっても、それぞれの反映確認を独立して管理します。

## 完了を判断する条件

`affected → proposed → testing → awaiting_deployment → resolved`を基本とします。手動で`resolved`へ変更する操作はありません。

解消判定には、同一資産・同一スキャナー・同一検査範囲の、新しい完全な成功結果が必要です。実行失敗や空のエラー出力、古い検査、別環境の結果、digestが一致しないイメージ検査では解消しません。Cloud Runでは稼働版の観測と検査の時差も確認します。再出現時は再オープンします。

```bash
python3 -m teate mark FINDING_ID --status awaiting_deployment --reason '修正PRをマージ、反映待ち'
python3 -m teate exception FINDING_ID --until 2026-12-01T00:00:00+09:00 --reason '暫定対策と期限'
```

期限付き例外は元の指摘を削除しません。失効後は自動的に未解消の集計へ戻ります。未検査、取得不能、48時間超の古い検査は別途表示します。

## 修正の自動化

まず、明示した指摘とバージョンに対する候補をTeate自身で用意できます。

```bash
python3 -m teate repair prepare --finding FINDING_ID --target 1.2.2
```

最大5件の`--finding`を指定できます。現在はnpm lockfile v3の単純な末端依存の安定版patchに限定し、公式npmレジストリの版・配布URL・SHA512を使って隔離worktreeに差分を作ります。元のcheckoutと台帳の解消状態は変更しません。前後のnpm検査、差分、候補の識別情報、必須テストが未完了であることを`.teate/repairs/JOB/`へ保存し、成功した指摘を`proposed`にします。修正版の入力は試行する候補の指定であり、安全性の保証ではありません。

プロジェクトテストの自動実行、自由なコード修正、候補の自動PR化はこのコマンドに含まれません。次のRenovate/CI経路へつなぐ際にも、既存の許可リスト・bot・対象commitの必須チェックを満たす必要があります。[制限と接続手順](docs/operations.md)を参照してください。

Renovateが登録済みリポジトリに設定PR・更新PRを作り、Teateがマージ可能な更新を判断します。既存リポジトリへ有効化するには、専用GitHub App等の必要権限を設定します。[運用手順](docs/operations.md)を参照してください。

v0.1の自動マージはnpmの既存`package.json`/`package-lock.json`のpatch更新に限定します。全更新パッケージの許可、安定版patch、公開後の待機期間、対象HEADの必須テスト、信頼するbot、差分の範囲を確認し、HEADが一致する場合だけGitHubへauto-mergeを要求します。新規依存・削除・install scriptや依存メタデータの変更・major/minor更新・その他の言語はレビューへ回します。PRのコードをTeateの権限で実行しません。

初期設定はパッケージとHomebrew更新の許可リストが空です。テストの実態と更新対象を確認してから、明示した範囲を自動化します。Renovate側の直接automergeは無効にし、Teateの判定を通します。npm以外の更新PRの準備はRenovateが担当します。

デプロイは各プロジェクトの既存CI/CDを利用します。Teate自身は新規GCPデプロイ、DB移行、OS再起動、秘密情報の更新を実行しません。`cloud-run` collectorはデプロイ後の実体を検証し、元の指摘を閉じる証拠を提供します。

## Macの定期実行

Mac上でこのリポジトリを配置し、`init`でMac固有の台帳設定を作ります。Python、`gh`、OSV-Scannerを用意してください。共有のNode/Python等はホスト資産、各プロジェクトの依存関係はsource資産として分離します。

```bash
python3 -m teate init --root /Users/you/projects --output config/local.json
python3 -m teate launch-agent --output "$HOME/Library/LaunchAgents/dev.teate.worker.plist" --repository OWNER/teate
launchctl bootstrap "gui/$(id -u)" "$HOME/Library/LaunchAgents/dev.teate.worker.plist"
```

plist生成だけではインストールされません。`gh`はMacのキーチェーンに保存した認証を利用し、plistにトークンを書きません。Macの資産を中央の`config/ci.json`へ登録してから、receiptを取り込めるようになります。未登録の資産を自動的に信頼しません。

Homebrewは許可したformulaとその依存関係を更新します。`mac.allowed_formulae`と`mac.allow_dependency_updates`、メンテナンス時間帯を明示してください。更新は直列化し、結果不明時は自動再送を止めます。

`process_names`に対象formulaの稼働プロセス名を設定し、稼働中なら更新を延期します。`automatic_formula_updates=true`にすると、定期workerが時間帯と停止状態を確認して更新します。更新に失敗した場合は処理を記録し、CVEの解消判定には別途再検査が必要です。

```bash
python3 -m teate mac-upgrade --formula EXPLICITLY_ALLOWED_FORMULA
python3 -m teate mac-upgrade --formula EXPLICITLY_ALLOWED_FORMULA --apply
```

## 証跡とGitHub連携

台帳は`.teate/ledger.sqlite3`、人が読む結果は`.teate/report.md`、機械向けの集計は`.teate/summary.json`です。receiptは`.teate/receipts/`へ追記します。

```bash
python3 -m teate ingest receipt.json
python3 -m teate github sync-issues --repository OWNER/teate
python3 -m teate github sync-issues --repository OWNER/teate --apply
python3 -m teate github publish --repository OWNER/teate --receipt receipt.json
```

Issuesの同期はdry-runが既定です。明示した`--apply`、または設定済み定期workerだけが書き込みます。作成済みIssueのマーカーで重複を防ぎ、解消確認後にクローズします。

GitHub Actionsでは、`teate-state`ブランチに圧縮SQLiteと集計を保存します。Mac等の証跡は`teate-receipts`ブランチへ内容ハッシュ付きで追記します。artifactは配布用で、永続台帳の代わりにはしません。台帳と設定を含むリポジトリは非公開にしてください。

v0.1のGitHub転送は1ファイル900KBまでです。上限に近づくと履歴を破棄せず停止します。対象数や履歴が増えたら、台帳を常駐サービス/PostgreSQLへ、証跡をオブジェクトストレージへ移す想定です。

## 検証

```bash
python3 -m unittest discover -s tests -v
python3 -m compileall -q teate scripts
```

環境間の誤クローズ、失敗・部分・古い検査、aliasによる重複、期限付き例外、稼働digest、patch判定、必須テスト、install script変更、更新対象のすり替えを検証します。
