# 導入チェックリスト

公開リポジトリにはソースコードと架空の設定例だけを含めます。実環境の資産一覧、認証、台帳、receipt、レポートは含めません。

1. Python 3.11以降、Git、使用するscannerを用意します。npm補助検査はnpmのlockfileだけが対象です。OSV-Scanner、Trivy、gcloud、Homebrewは利用するcollectorに応じて別途必要です。
2. 各ホストで`python3 -m teate init --root /path/to/projects --output config/local.json`を実行します。他の環境のパスやhost IDをコピーして実ホストの確認済み情報として扱いません。
3. `agent cycle`と`agent render`を実行し、指摘だけでなく未確認範囲も確認します。接続が失敗した対象や未対応言語は安全確認済みになりません。
4. 中央のGitHub同期を使う場合は、公開ソースとは別に非公開の運用リポジトリを用意し、実資産を登録します。`TEATE_OPERATIONS_ENABLED=true`を明示するまで運用workflowは起動しません。
5. 更新を自動化する前に、専用bot、必要なテスト、パッケージ・formulaの許可リスト、メンテナンス時間帯、実環境の再検査を設定します。LLMの文や外部勧告は操作の許可になりません。

Macのlaunch agentはplistの生成だけではインストールされません。Cloud Runの観測には既存の適切な読み取り認証とAPI通信が必要です。ソースの修正候補やPRマージだけで、本番の指摘を解消扱いにはしません。

詳細は[README](../README.md)、[運用手順](operations.md)、[小型モデル向けの契約](small-model.md)、[セキュリティ方針](../SECURITY.md)を参照してください。
