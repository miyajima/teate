# Teate — てあて

Mac・VPS・クラウドの脆弱性を調べ、「何が未対応か」「修正を確認できたか」を管理するCLIです。
**下の手順でインストールから初回検査まで進められます。通常の検査にLLM・GitHubアカウント・APIキーは不要です。**

Teate is an open-source CLI for vulnerability tracking and verified remediation.
Python 3.11+; no third-party Python packages. [MIT License](LICENSE).

## 1. Teateをダウンロードする

[ZIPをダウンロード](https://github.com/miyajima/teate/archive/refs/heads/main.zip)して展開し、ターミナルで`teate-main`フォルダーを開きます。アプリや台帳はWebへ公開しないため、ホームディレクトリなど、Web公開ディレクトリの外へ置いてください。

コマンドで取得する場合は次のとおりです。すでにTeateを取得済みなら、そのフォルダーで次のステップへ進めます。

**Mac / Linux（curl・tarを使用）**

```bash
curl -fL https://github.com/miyajima/teate/archive/refs/heads/main.tar.gz -o teate.tar.gz
tar -xzf teate.tar.gz
cd teate-main
```

最小構成のUbuntuでcurlがない場合だけ、先に`sudo apt-get update`と`sudo apt-get install -y curl`を実行してください。

**Windows（PowerShell）**

```powershell
Invoke-WebRequest https://github.com/miyajima/teate/archive/refs/heads/main.zip -OutFile teate.zip
Expand-Archive teate.zip -DestinationPath .
cd teate-main
```

## 2. 必要なツールを一括インストールする

**Mac / Linux**

```bash
bash scripts/install.sh --all
source .teate/env.sh
```

通常ユーザーで実行してください。OSのパッケージ導入やHomebrewの初回設定で、管理者パスワードなどを求められる場合があります。

**Windows（PowerShell）**

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -All
```

Windowsでは**WSL2のUbuntu上でTeateを動かします**。Windowsネイティブ版ではありません。WSL2が未導入ならセットアップを開始します。管理者権限・再起動・Ubuntuのユーザー作成を求められた場合は完了させ、同じコマンドを再実行してください。既存のWSL1環境は事前にWSL2へ変更します。[MicrosoftのWSL手順](https://learn.microsoft.com/windows/wsl/install)

インストール後、Windowsでは次でUbuntuを開きます。**以降の操作はこのUbuntuの中で行います。**

```powershell
wsl -d Ubuntu-24.04
```

Ubuntuが開いたら実行します。

```bash
cd ~/teate
source .teate/env.sh
```

Windows用スクリプトは初回に公開ソースをUbuntuの`~/teate`へコピーします。既存の`~/teate`は上書きしません。更新する場合は、そのLinux側のTeateも更新してください。

### 何が入る？

| ツール | 用途 | 通常導入 | `--all` / `-All` |
|---|---|---|---|
| Python・Git | Teateの実行、検査対象の識別 | ○ | ○ |
| OSV-Scanner | 複数言語の依存ライブラリ検査 | ○ | ○ |
| Node.js・npm | npmの補助検査・修正候補の検証 | — | ○ |
| Trivy | コンテナイメージ検査 | — | ○ |
| GitHub CLI (`gh`) | 非公開台帳の共有・GitHub連携 | — | ○ |
| Google Cloud CLI (`gcloud`) | Cloud Runの実体確認 | — | ○ |
| Codex CLI | 任意のLLM例外調査 | — | ○ |
| bubblewrap（Linux） | 修正候補のテストを隔離して実行 | — | ○ |

**検査だけなら`--all`（Windowsは`-All`）を外すと軽量です。** MacはHomebrewがなければ公式インストーラーを実行します。Linuxはapt-get / dnfを利用し、Python 3.11以上が必要です。目安はUbuntu 24.04以降・Debian 12以降・新しいFedora。Mac / Linuxはamd64・arm64が対象です。

Python・Git・LinuxのbubblewrapはOSのパッケージ管理から導入し、その他のツールは主にTeate内の`.teate/`へ入れます。直接取得するバイナリは固定版・SHA256照合、Codexは固定版の公式npmパッケージを使用します。シェル設定は自動で書き換えません。認証情報や検査対象の登録も自動では行いません。

実行前に内容だけ見たい場合は`bash scripts/install.sh --all --dry-run`、Windowsは`powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -All -DryRun`を使います。途中で失敗したら原因を確認して再実行できます。TLS検証や通信制限を緩めることはしません。

## 3. 検査対象を登録する（初回だけ）

例えば、アプリが`/var/www/myapp`にあるVPSでは、**1つ上の`/var/www`**を指定します。

```bash
umask 077
python3 -m teate init --root /var/www --output config/local.json
```

Macで`/Users/you/projects/myapp`を調べる場合は、`/var/www`を`/Users/you/projects`へ置き換えます。指定した親フォルダーの直下から、Gitリポジトリまたは対応する依存ファイルがあるアプリを登録します。`config/local.json`の`assets`に目的のアプリがあることを確認してください。対象がない場合は未登録です。既存の設定は`init`で上書きせず、編集します。

**アプリはGit管理されていなくても検査できます。** Gitコマンドはインストールが必要ですが、GitHubへアプリをアップする必要はありません。

<details>
<summary>アプリを1つだけ、パスで直接登録する場合</summary>

初回用の`config/local.json`の例です。`path`を実際のアプリの絶対パスへ変更してください。既存の設定がある場合は上書きせず、`assets`へ追加します。

```json
{
  "schema_version": 1,
  "state_dir": "../.teate",
  "policy": {"max_scan_age_hours": 48, "automation": {"enabled": false}},
  "assets": [
    {
      "id": "source:vps:myapp",
      "project": "myapp",
      "environment": "production",
      "kind": "source",
      "path": "/var/www/myapp",
      "exposure": "unknown"
    }
  ]
}
```

対象ソースを読めるユーザーで実行してください。lockfileなど対応する依存情報がない場合は未確認になります。WindowsからVPSを調べる場合も、WSL内からそのVPSが自動的に見えるわけではありません。VPS上で実行するか、別途検査用コピーを用意します。

</details>

## 4. 検査して、日本語で結果を見る

**Teateのフォルダーで**次の2コマンドを順番に実行します。最初の検査は少し時間がかかります。

```bash
python3 -m teate agent cycle --scanner osv
python3 -m teate agent render
```

最初のコマンドが公式情報の更新・検査・台帳更新を行い、2つ目が結果を表示します。通常の検査ではアプリのソース変更・依存インストール・本番への反映は行いません。OSVは依存パッケージ名・版などを外部サービスへ問い合わせます。

OSVに接続できず、npmの`package-lock.json`だけを調べる場合は次を使います。Node/npmは一括導入の`--all`に含まれます。

```bash
python3 -m teate agent cycle --scanner npm-audit
python3 -m teate agent render
```

npmレジストリへ依存情報を送ります。**npm以外のRustなどは検査できず、未確認のままです。**

## 5. 結果を読む

| 表示 | 意味 |
|---|---|
| 登録資産 | 登録したアプリ・環境の数 |
| 未解消 | まだ修正を確認できていない指摘 |
| 未確認 | 検査失敗・対象外・古い結果などで、十分に確認できていない資産 |
| 期限超過 | 対応期限を過ぎた未解消の指摘 |
| 解消確認 | 新しい検査で解消を確認できた指摘 |

**「未確認」は安全という意味ではありません。** 指摘0件でも未確認が残れば、環境全体の安全性は判定できません。

終了コードは`0`＝処理成功、`1`＝部分検査・未確認・情報更新失敗あり、`2`＝エラーです。`0`でも脆弱性が見つかる場合があります。`1`でも続けて`agent render`で結果を確認してください。2コマンドを`&&`でつながず、個別に実行します。

詳細は`python3 -m teate report`、対応一覧は`python3 -m teate plan`で見られます。これは保存済みの結果の参照で、再検査はしません。画面を自作する場合は`.teate/summary.json`を利用できます。

## 2回目以降はこの3行

Teateのフォルダーで実行します。インストールと`init`は毎回不要です。

```bash
source .teate/env.sh
python3 -m teate agent cycle --scanner osv
python3 -m teate agent render
```

VPSで毎日動かす場合はcronやsystemd timerで同じユーザー・作業フォルダー・Python・PATHを指定します。検査結果は`.teate/`、対象設定は`config/local.json`に残るので、両方を非公開でバックアップしてください。

## Codexから「Teateで調べて」と頼むためのスキル

Teate用の[スキル](.agents/skills/teate/SKILL.md)を同梱しています。TeateのフォルダーでCodexを使う場合は、そのまま検出できます。スキル自体にLLMやツールは含まれず、上で導入したTeateを固定手順で操作するためのものです。

**ほかのフォルダーからも使いたい場合**は、Teateのフォルダーで次を1回実行します。ユーザー共通の`~/.agents/skills/teate`へ、スキルの公開ファイルだけをコピーします。

```bash
python3 scripts/install_skill.py --user
```

プロジェクトを限定するなら、代わりに次を使います。指定したフォルダーは実在するものに置き換えてください。

```bash
python3 scripts/install_skill.py --project /path/to/your-project
```

WindowsではWSLのUbuntu内で実行します。既存のスキルが同じ内容なら何も変更せず、内容が異なる場合は上書きせずに止まります。更新時は既存の内容を確認して別の場所へ移動してから再実行してください。

Codexで次のように依頼できます。Teateの配置先も伝えると、別の台帳を使ってしまうことを防げます。

```text
$teate Teateは /path/to/teate にあります。登録済みの脆弱性を検査して、今日やることを日本語で教えて。
$teate 保存済みの対応状況だけ見せて。再検査はしないで。
$teate 対応可能な修正候補を作り、テスト結果と残っている確認事項を教えて。
```

スキルは通常の検査・定型報告に追加のモデルを呼びません。詳しい導入・一次情報調査の説明は必要なときだけ読み込みます。検出されない場合はCodexを開き直してください。[Codexのスキル仕様](https://developers.openai.com/codex/skills/)

## 修正・LLM・クラウド連携は必要になってから

- **修正候補の作成**: `agent cycle --scanner osv --prepare`。現在はGit管理された変更のないアプリの、限定的なnpm依存patch更新が対象です。Gitなしの自動修正は未対応です。
- **テストの実行**: プロジェクトごとのコマンド設定が必要です。sandboxの実行権限も確認します。インストールだけではテスト成功・解消扱いにはしません。
- **LLM例外調査**: 上記へ`--llm codex`を追加し、事前に公式Codex CLIの`codex login`でChatGPT認証します。通常はLLM呼び出し0回、例外は最大1回。APIキーへの切替はしません。[手順と制限](docs/small-model.md)
- **GitHub / Cloud Run**: ツールを入れるだけでは接続されません。必要な認証・権限・対象を別途設定します。インストーラーはログイン・権限追加・デプロイを実行しません。[運用手順](docs/operations.md)

**公開するのはTeateのコードだけです。** 実際の設定・台帳・レポートは、Web公開ディレクトリや公開GitHubリポジトリへ置かないでください。共有するなら別の非公開リポジトリを使います。この公開リポジトリの別ブランチも公開です。公開CIは合成データのテストのみで、運用workflowは非公開repoで明示的に有効化する必要があります。[導入チェックリスト](docs/handoff.md)

---

以下は運用を詳しく設定する方向けの説明です。

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
