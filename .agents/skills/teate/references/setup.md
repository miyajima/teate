# 導入・初期登録が必要なときだけ読む

対象のTeate配置先・アプリのパス・利用したい機能を確認する。既存の設定を優先し、導入の依頼範囲で実行する。管理クラウドの通信・書き込み制限はそのまま使う。

## Teateの取得と依存ツール

Teateが未配置なら、公式公開リポジトリ`https://github.com/miyajima/teate`をcloneするかZIPを取得する。Web公開ディレクトリの外へ置く。READMEのインストール手順を使う。Python 3.11以上、mise、OSV、Node/npm、sandbox-runtime、feedparserをインストーラーで用意する。

Mac / Linuxで、Teateのフォルダーから通常ユーザーとして実行する：

```bash
bash scripts/install.sh
source .teate/env.sh
```

全ツールの導入も依頼されている場合は`bash scripts/install.sh --all`を使う。Trivy、gh、gcloud、任意のCodexが追加される。Linuxのbubblewrap/socatは基本構成。MacはHomebrew、Linuxはapt-get / dnfを使う。OSの権限不足・古いPython・通信失敗は報告し、制限を迂回しない。

WindowsのPowerShellでは次を使う。全ツールは`-All`を追加する：

```powershell
powershell -ExecutionPolicy Bypass -File scripts/install.ps1
```

WindowsネイティブのTeateではなく、WSL2のUbuntuで実行する。初回はOSのセットアップ・再起動・Linuxユーザー作成が必要な場合がある。完了後に同じコマンドで再開し、`wsl -d Ubuntu-24.04`を開いて`cd ~/teate`、`source .teate/env.sh`を実行する。WindowsからリモートVPSのソースが自動的に見えるとは扱わない。

## 初回の登録

例としてアプリが`/var/www/myapp`なら、親の`/var/www`を指定する：

```bash
umask 077
python3 -m teate init --root /var/www --output config/local.json
```

親の直下にある複数のアプリが対象になり得るので、登録結果の`assets`が依頼範囲と一致するか確認する。0件・目的のアプリなしは登録成功としない。既存の`config/local.json`は上書き・削除しない。対象の登録例はTeateのdocs/operations.mdにある。

アプリ自身はGit管理不要。ローカルディレクトリーの候補作成もGitなしで動く。対応するlockfile等がなければ未確認になる。SSH取得・Git clone・VPS内実行のどれを使うかは依頼と接続状態に合わせ、未指定のリモートホストへ接続しない。

## 認証・修正候補

依存ツールを入れるだけではGitHub・Cloud Run・Codexへ接続されない。既存の設定済みidentityを利用し、認証情報の内容を読んだりコピーしたりしない。Codex例外調査は信頼できる環境の公式CLIでChatGPT認証を使う。API課金への切替はしない。

修正候補のテストには対象ごとの明示的なテスト設定と、利用可能なOS sandboxが必要。sandboxやプロジェクト依存が不足しても、非隔離実行へ切り替えない。詳細はTeateの`docs/operations.md`と`docs/small-model.md`を必要な箇所だけ読む。

自動修復はglobal policyと資産ごとのremediationを登録する。許可パッケージ、実際のテスト、本番反映、読み取り専用の観測・health、rollback、runtime資産が必要。AIは不足を示し、運用者の指定なしに許可や手順を発明しない。フックはソース/候補/台帳の外で管理し、実行ファイルと追加スクリプトをSHA256で固定する。
