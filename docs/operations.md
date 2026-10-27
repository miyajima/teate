# 運用・接続手順

## v0.4の日次処理とテスト

`agent cycle --scanner npm-audit --prepare`で、検査・公式フィード差分・修正版候補の調査・対応済みの候補作成・設定済みのテスト・再検査まで実行します。通常はモデル呼び出し0回です。KEVに加えてJPCERT/CC・JVN・Node.js公式RSS/Atomを取得し、最終成功時点から48時間重複、初回7日を中心に変更を記録します。取得不能は未確認で、成功日時を進めません。RSSの掲載自体から、管理対象の利用・影響・悪用・修正済みを判断しません。

修正版はscannerの構造化フィールドか、対象packageに一致するGitHub公式Advisory APIから取得し、公式npmレジストリで版・配布元・SHA512・公開時刻を検証します。新しい版はあくまで候補で、対象の指摘が実際に消えるかを再検査します。台帳の`fixed_versions`を推測で書き換えません。

各source資産の非公開設定に、操作者が`verification`を明示できます。

```json
{
  "verification": {
    "commands": [
      {"name": "unit", "argv": ["python3", "-m", "unittest", "discover", "-s", "tests", "-q"], "cwd": ".", "timeout_seconds": 60}
    ],
    "discard_outputs": [],
    "context_files": ["src/example.py"]
  }
}
```

これは資産定義へ追加する部分設定の例です。対象に実在するテストへ置き換えてください。コマンドは最大5件、各1〜120秒、shell展開なしで実行します。Linuxではbubblewrap、macOSでは利用可能なsandbox-execを使い、ネットワークとホスト認証情報へのアクセスを制限します。sandboxの不足・利用拒否時は実行を止め、非sandbox実行へ切り替えません。依存インストールやネットワークを伴うテストは自動では行いません。候補に必要なツール・依存を用意する方法は操作者の検討事項です。

`discard_outputs`はテストが生成する既存のtrackedファイルを候補作成直後の内容へ戻すための明示リストです。依存manifestやlockfile、管理外パスには使えません。許可外の差分が残れば検証失敗です。`context_files`は例外調査に渡してよいコードだけを最大2ファイル選び、秘密情報や認証を含めません。ローカルテストが通っても、対象commitの必須GitHub CI・信頼bot・許可リスト・待機期間は代替しません。

非公開GitHubのassessment workflowは新しいcycleを使います。`TEATE_PREPARE_CANDIDATES=true`を明示すると候補作成まで進めます。GitHub ActionsへCodex認証を複製しません。公式情報の差分履歴とモデル試行記録は`control-state.json.gz`に保存し、永続化容量が不足した場合は履歴を破棄せず停止します。

## ローカル修正候補の作成（v0.3）

`repair prepare --finding ID --target VERSION`は、登録済み・同一ホスト・変更のないGit checkoutだけを扱います。入力は操作者が明示し、LLMの選択応答や勧告本文からこのコマンドを自動起動しません。最大5件、npm lockfile v3、同一major/minorの安定版patch、単純な末端依存が対象です。固定された依存指定、依存グラフ・ライセンス・実行条件の変更、install hook、symlink、未対応の指定はレビューへ回します。

まず元のソースをnpmで再検査し、指摘が現在も存在することを確認します。公式npmレジストリで指定版と配布情報を確認し、checkout hookを無効にした隔離worktreeでバージョン・URL・SHA512だけを更新します。依存関係をインストールせず、プロジェクトのscriptも実行しません。対象範囲の再検査が成功し、対象の指摘が消え、新しい指摘が増えていない候補だけを`candidate_ready`とします。Rust等の未検査範囲は`unverified_scopes`に残ります。

候補のscanは中央台帳へ取り込まれません。元の指摘は`proposed`に進み、日次レポートは`review_prepared_candidate`を示します。`fixed_versions`、優先度、期限、解消状態を推測で書き換えません。結果は`.teate/repairs/JOB/result.json`、資産ごとの`baseline.json`、`registry.json`、`candidate.json`、`candidate.patch`です。途中で失敗した作業コピーも調査用に保持し、同じ呼び出し内で自動再試行しません。

終了コード0は候補作成がすべて成功、1はレビューに回った資産あり、2は入力や設定のエラーです。0でもテスト・マージ・デプロイ・解消は完了していません。プロジェクトテストとcommitを限定した必須CI、認証済みのPR作成、反映後の再検査は既存の接続経路で行います。候補作成の許可と自動マージの許可は独立しています。

任意のCodexサブスク接続は[small-model.md](small-model.md)の`codex status`と`agent advise`を使います。認証情報をGitHub Actionsのsecretへ複製せず、まず既存のChatGPTログインを持つMac等で実行してください。

## 最初の接続

1. 公開ソースとは別に、非公開の`OWNER/teate-ops`等へソースを配置します。GitHubのpublicリポジトリには台帳・レポート・receiptを送信できません。公開repo内の別ブランチも公開です。
2. 非公開の運用リポジトリで`config/ci.example.json`を参考に`config/ci.json`へ実際の管理資産を登録します。配布時の管理対象は空です。sourceの`repository`は確認済みの`owner/name`だけを指定します。
3. GitHub Actionsの`CI`を実行します。
4. assessment用の専用認証を`TEATE_GITHUB_TOKEN`へ設定します。GitHub Appを使う場合は、そのAppの短命なinstallation tokenをworkflowで発行して渡してください。通常の`GITHUB_TOKEN`は当該リポジトリ用なので、別の非公開プロジェクトを読めません。設定不足のプロジェクトは未確認として残ります。
5. 非公開の運用リポジトリで`TEATE_OPERATIONS_ENABLED=true`をリポジトリ変数へ設定します。その後`Teate assessment`を手動実行し、`teate-state`のreportとIssueを確認します。以後は07:10 JSTに日次起動します。GitHubのscheduleは遅延し得ます。公開リポジトリでは運用jobを起動しません。

Macに設定する認証は中央Teateへの読み書きに限定します。修正botの認証をMacへ配布する必要はありません。クラウドの観測には各プロジェクトの読み取り権限を使い、更新・デプロイの権限とは分けます。

## 修正PRと自動マージ

1. 専用の更新botに、登録済みリポジトリのContents/Pull requests/Checksの必要権限を設定し、`TEATE_RENOVATE_TOKEN`で渡します。
2. 非公開の運用リポジトリで`TEATE_OPERATIONS_ENABLED=true`と`TEATE_RENOVATE_ENABLED=true`をリポジトリ変数へ設定します。
3. 初回にRenovateが作る設定PRを確認・反映します。Teateは登録済みリポジトリだけを処理します。
4. `policy.json`の`trusted_bots`を実際のbotログインに合わせます。ユーザー個人のログインを安易にbot扱いしません。
5. `allowed_packages`へ自動化するパッケージを列挙し、`required_checks`へ実際のテストjob名を設定します。各対象repoで、必須status checkを含むbranch rulesを設定します。
6. `Teate remediation`が07:40 JSTにRenovateを実行し、更新PRを判定します。承認済みの条件を満たすpatchのみauto-mergeを要求します。PRのテストがまだ完了していなければ次の実行で再判定します。

緊急対応は優先順位を上げます。通常の自動マージに必要なテストや対象確認を緊急扱いで省略しません。実際の悪用や悪意あるパッケージには、隔離・証跡保全・認証情報への影響調査が必要になるため、単純なバージョン更新で完了にしません。

## クラウド稼働版

`cloud-run`資産をcollectorが実行できる環境の設定へ追加します。`gcloud`のidentityは既存のSDK/CLI設定を利用し、Teateはログイン・権限変更を実行しません。

collectorはCloud Run Serviceと全到達可能revisionをGETし、Readyとimmutable image digestを確認します。Trivyで全digestを検査できた結果だけを、対応完了の証拠にできます。Cloud Runの管理対象外のサービスやVMは、v0.1では別collectorの追加が必要です。

Cloud Runにデプロイ済みのイメージは作業用checkoutの状態とは独立して評価します。CIで修正しても本番へ反映されていなければ、sourceとproductionで状態が異なるまま残ります。ロールバックで脆弱なイメージに戻った場合、再検査で再オープンします。

## 通信先

- OSV-Scanner: OSV API、必要に応じて公式データ配信先。到達不能なら未確認とします。
- npm補助検査: `registry.npmjs.org`。`npm audit --package-lock-only --ignore-scripts`を実行し、依存パッケージをインストールしません。
- KEV: `raw.githubusercontent.com/cisagov/kev-data`。照合元の取得日時と公開日時を証跡へ保存します。
- GitHub: API、登録済みrepo、公式scannerのrelease。
- Trivy: 脆弱性DB配信元と設定したイメージレジストリ。
- Cloud Run: 設定済みGCP API。

接続できない通信先に対し、プロキシを外すなどの回避は行いません。許可されたネットワーク設定で接続するか、結果を未確認として扱います。

## 対応記録の運用

同じ指摘を再処理しても同じIssueを使います。scanは内容ハッシュで重複排除します。判定は資産・scanner・scopeごとに直列化します。観測時刻が古いreceiptは保存しますが、現在の状態を上書きしません。

JSON scanner結果を手動変換するときは、元の検査時刻を`normalize --observed-at`へ指定します。今日取り込んだという理由で、過去の検査を新しい検査として扱わないでください。

SQLiteとreceiptはprivateなデータです。ソースの公開ブランチや公開レポートへ配置しないでください。Teateはソースコードや秘密情報の値をreceiptへ収集しません。
