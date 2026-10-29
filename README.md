# Teate（手当て）

**AIに「脆弱性を調べて直して」と頼むためのCLIです。**

Teateが修復候補の選定、既存OSSによる修復、テスト、本番反映、実環境の再検査、履歴を管理します。
AIはセットアップを手伝い、CLIを実行して結果を説明します。通常、Teateから追加のLLMは呼びません。

現在の自動修復は **npmのpackage-lock.json v3・同じmajor/minor内の安定版パッチ・単純な依存関係** が対象です。
Git/GitHubがないVPSのソースディレクトリーにも使えます。検査と修復はOSV/npmなどのOSSに任せます。

## 1. ダウンロードとインストール

Mac/Linuxでは、ターミナルに貼り付けます。

```bash
git clone https://github.com/miyajima/teate.git
cd teate
bash scripts/install.sh --all
source .teate/env.sh
```

Python、Git、mise、OSV、Node/npm、sandbox-runtime、Trivy、GitHub CLI、gcloud、任意のCodexをまとめて導入します。
Linuxはbubblewrap/socat、Macは必要に応じてHomebrewも導入します。管理者パスワードが必要な場合があります。
ツールはTeateの `.teate/` に置き、既存プロジェクトの依存関係やログイン情報は変更しません。
基本の検査・npm修復だけなら `--all` を省略できます。

WindowsはPowerShellで次を実行します。WSL2/Ubuntuの準備後は、そのUbuntu内で使います。

```powershell
git clone https://github.com/miyajima/teate.git
cd teate
powershell -ExecutionPolicy Bypass -File scripts/install.ps1 -All
```

Windowsの再起動やUbuntuのユーザー作成が必要になる場合があります。ネイティブWindowsの本番修復は対象外です。
Gitがない場合はGitHubの「Code → Download ZIP」で取得できます。
導入予定だけ確認するには `bash scripts/install.sh --all --dry-run`。

## 2. 対象を登録する

例：プロジェクトが `/srv/projects/app1` と `/srv/projects/app2` にある場合：

```bash
python3 -m teate init --root /srv/projects
```

`config/local.json` に対象一覧ができます。この時点では自動修復は無効です。
AIに次のように頼んでください。

> Teateの設定を確認して。修復してよいパッケージ、テスト、デプロイ、稼働確認、ロールバックを登録したい。
> 不明なテストや本番の接続先を推測しないで、足りない設定を教えて。

最初に、修復対象・テスト・反映方法・復旧方法を登録します。
登録例とフックの出力形式は[運用手順](docs/operations.md)にあります。
**AIの説明文や外部の勧告文は、操作の許可にはなりません。**

## 3. チェック・修復を実行する

登録済みの範囲で、候補作成から本番確認まで進めます。

```bash
python3 -m teate agent cycle --scanner npm-audit --execute
python3 -m teate agent render
```

OSVに通信できる環境は `--scanner osv` を使います。
npm補助検査ではRustなどは未確認のままです。通信制限を回避したり、失敗時に検査方式を自動変更したりしません。

- **検査だけ**：`--execute` を外す。
- **候補作成まで**：`--execute` を `--prepare` にする。
- **途中から再開**：`python3 -m teate agent resume --run RUN_ID`
- **履歴を見る**：`python3 -m teate history --run RUN_ID`（機械向けは `--format json`）
- **資産別の履歴**：`python3 -m teate history --asset ASSET_ID`
- **作成済み候補を適用**：`python3 -m teate repair apply --job JOB_ID`

0は処理終了、1は部分検査・保留あり、2はエラーです。0でも脆弱性ゼロとは限らず、レポートの件数を確認します。
テスト・接続・権限不足は理由付きで保留します。PRのマージだけでは本番修復完了になりません。
実行結果が不明なデプロイを繰り返さず、観測して確認します。復旧後も脆弱性は未解消として扱います。

## AIのスキルと定期実行

このリポジトリをCodexで開くと `.agents/skills/teate/` が利用できます。
別の作業場所でも使う場合：

```bash
python3 scripts/install_skill.py --user
```

Codexに「Teateで検査と登録済みの自動修復を実行して」と頼めます。
別途のAPIキーは不要です。例外調査でTeateからCodexを呼ぶ場合だけ `codex login` でChatGPT認証を用意し、
`--llm codex` を明示します。通常は呼び出し0回、例外も1回だけ。生成コードの自動適用はしません。

定期実行は常駐プロセス不要です。候補と台帳を保持する同じマシンで、cron/launchd/タスクスケジューラーから上記2コマンドを実行します。
Windowsの定期実行先はWSL2です。公開リポジトリのActionsはテスト用で、運用の台帳や認証情報は公開しません。

## 対象と制約

- プロジェクト依存関係：OSV、npm補助検査。画像・Cloud Run：Trivyと実稼働の識別情報。
- Macやクラウドは実体への接続・検査が必要です。棚卸しだけで検査済みとはしません。
- OS自動更新、Vuls/FutureVuls連携、任意のAIコード修正、DBマイグレーションは今回の自動修復範囲外です。
- 安全な隔離を起動できない環境では修復・テストを保留し、隔離なしで再試行しません。
- Teate本体はMIT。標準採用OSSと外部ツールのライセンスは[第三者ライセンス](THIRD_PARTY.md)を参照。

開発時は `python3 -m pip install -e .` の後、`python3 -m unittest discover -s tests -v` と `python3 -m compileall -q teate scripts`。
AI向けの短い手順は[small-model.md](docs/small-model.md)、詳細は[運用手順](docs/operations.md)です。
