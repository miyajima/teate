# 修復の登録と運用（v0.5）

Teateは「候補 → テスト → 反映 → 稼働観測 → 正常性確認 → 再検査」を記録します。
修復はnpm/OSV、隔離はsandbox-runtime、ツールの取得・展開はmise、フィード解析はfeedparserに委譲します。
本番コマンドは運用者の登録が必要です。AIや外部テキストからコマンドを自動承認しません。

## 許可する設定

`config/local.json` の対象source資産に、以下を追加します。これは契約例です。
`/opt/teate-hooks/*` は実際の運用手順を実装した、ソースの外にある運用者管理の実行ファイルに置き換えます。
Teateが汎用のVPS上書きや任意のSSH接続を行うことはありません。

```json
{
  "verification": {
    "install_dependencies": true,
    "commands": [{"name": "test", "argv": ["npm", "test"], "timeout_seconds": 120}]
  },
  "remediation": {
    "enabled": true,
    "mode": "local",
    "runtime_assets": ["app-production"],
    "deploy": {
      "argv": ["/opt/teate-hooks/deploy", "{candidate}", "{run_id}", "{candidate_id}"],
      "sha256": "実行ファイルのSHA256"
    },
    "observe": {
      "argv": ["/opt/teate-hooks/observe", "{run_id}", "{candidate_id}"],
      "sha256": "実行ファイルのSHA256"
    },
    "health": {
      "argv": ["/opt/teate-hooks/health", "{run_id}", "{release_id}"],
      "sha256": "実行ファイルのSHA256"
    },
    "rollback": {
      "argv": ["/opt/teate-hooks/rollback", "{run_id}", "{release_id}"],
      "sha256": "実行ファイルのSHA256"
    }
  }
}
```

グローバルの `policy.automation.enabled: true` と、`allowed_packages: ["対象パッケージ名"]` も必要です。
既存の許可は移行時に拡大しません。公開後の待機時間は `minimum_release_age_hours`（省略時336時間）です。
`verification.commands` は最大5件、各1–120秒。準備のnpm ciは明示時だけネットワークを使い、ライフサイクルスクリプトを無効にします。
テストはネットワークなし・ホスト認証なしで実行します。必須のプロジェクトテストを省略しません。

SHA256はMac/Linuxで次のように確認できます。

```bash
python3 -c 'import hashlib,pathlib; print(hashlib.sha256(pathlib.Path("/opt/teate-hooks/deploy").read_bytes()).hexdigest())'
```

フックに共通する任意設定：`timeout_seconds`（1–600秒）、絶対パスの`cwd`、渡す既存環境変数名の`env_names`。
秘密値は設定ファイルに書かず、必要最小限の既存認証を利用します。認証内容は台帳に保存しません。
インタープリター経由の場合は、追加の`files: {"/opt/teate-hooks/deploy.py": "SHA256"}`でスクリプトも固定します。
`argv`の実行ファイルは絶対パス必須。置換できるのは上記のトークンと`{head_sha}`だけで、シェル評価はありません。
フックはプロジェクトのテストと異なり、運用者が承認した本番操作です。ソース・候補・台帳内のフックを登録しないでください。

## フックのJSON契約

標準出力は最大12KBのJSONオブジェクトだけ。生ログや秘密は出力しません。
全応答に同じ`run_id`を含め、想定外のフィールドは拒否します。正常終了は終了コード0。

| フック | 必須の出力 |
|---|---|
| deploy | `status: "deployed"`、`run_id`、`candidate_id`、`release_id`、`previous_release_id` |
| observe（読み取り専用） | `status: "success"`、`deployment: "applied"`、同じrun/candidate/release ID、`previous_release_id` |
| health（読み取り専用） | `run_id`、対象`release_id`、`healthy: true`または`false` |
| rollback | `run_id`、`status: "rolled_back"`、戻した`release_id` |

画像・Cloud Runへのdeploy/observeは、実際に配備した不変のダイジェスト配列 `runtime_digests` も返します。
Cloud Runはトラフィック・タグで到達できる全リビジョンのイメージと一致する必要があります。
ソース型runtime資産は、実際の稼働リリースであることをobserveが確認し、候補のlockfile集合・ハッシュと一致してから再検査します。
本番資産は別IDで `assets` に登録してください。同じプロジェクトでもsourceとproductionの状態は別です。

observeは未反映を`deployment: "not_applied"`、判定不能を`"unknown"`として報告できます。
タイムアウト・不正JSON・接続不能は未確認です。変更コマンドを再送しません。
deployが`status: "failed"`を返して旧/新リリースを識別できる場合や、確認済み新リリースのhealthがfalseの場合はrollbackを1回だけ送ります。
次回resumeでobserveが`deployment: "rolled_back"`かつ旧release ID、healthがtrueと確認できて初めて復旧確認です。脆弱性の解消にはしません。
ソースへ修正版が戻っていなければ`runtime_verified_source_sync_still_required`として残します。

## GitHub経由

`mode: "github"`、`repository: "owner/repo"`、`base_branch: "main"`を登録します。
`asset.repository`の登録先との一致、許可されたbase branch、`trusted_bots`に登録された実際の発行者、
同じhead SHAの`required_checks`、パッケージ許可・待機期間・差分の条件をすべて満たしてからauto-mergeを要求します。
Teateは検証済みlockfileだけのブランチ・PRをAPIで作成し、マージ・既存CI/CDの完了を観測します。
PR本文は固定文で、台帳やスキャンの生データを公開しません。証跡/Issueを送る先は従来どおり非公開リポジトリ必須です。

このモードは既存CI/CDのdeployを使うため`deploy`フック不要ですが、observe/health/rollbackとruntime登録は必要です。
CI/CDはrun ID（ブランチ`teate/repair-RUN_ID`）とcandidate IDを観測可能なリリース情報へ結び付けてください。
候補のファイル集合を同じ正規化SHA256で表すcandidate IDは`history --run ID --format json`に保存した`record.candidate_files`から計算できます。
変更結果が不明なPR作成は同名ブランチ・内容・PRを読み取り照合します。不完全な作成はレビュー待ちで、推測して再作成しません。
実行は候補ディレクトリーとSQLiteを保持するワーカーで行ってください。毎回消えるCIワーカーへの候補コピーや認証の永続化は行いません。

## 状態と履歴

```bash
python3 -m teate agent cycle --scanner npm-audit --execute
python3 -m teate agent render
python3 -m teate history --run RUN_ID --format json
python3 -m teate agent resume --run RUN_ID
```

`blocked`は設定・テスト・接続待ち、`awaiting_deployment`は反映設定待ち、`awaiting_ci`はCI/マージ待ち、
`verification_pending`は実環境確認待ち、`uncertain`は変更結果不明、`stale`は再作成が必要、
`rolled_back`は復旧確認済み・脆弱性未解消、`verified`は稼働先と元ソースの再検査完了です。

SQLiteのrun/stepは操作直前のintentと結果を保存し、同じ資産の同時実行を防ぎます。
同じrunを再開すれば、終了したデプロイ/マージ/rollbackを繰り返しません。
候補作成そのものが未完了のrunは、resumeしても候補を再作成しません。
表示された前提を解決してから次のagent cycleで新しい候補を作成してください。
ソース・候補・設定が変わった場合は候補を再評価し、未確認の変更操作は自動再送しません。
コード生成例外のreview patchは自動適用に取り込みません。

v0.4からは初回起動時に`ledger.sqlite3.pre-v05`を作ってテーブルを追加し、既存ID・履歴・例外・期限を維持します。
過去の候補は証跡として残りますが、v0.5の差分・テスト・設定条件を満たすまで適用しません。
日次処理は最大5件ずつ扱い、最上位候補を維持しながら残りを巡回して、先頭の保留案件による滞留を防ぎます。

## 開発時の検証

```bash
python3 -m pip install -e .
python3 -m unittest discover -s tests -v
python3 -m compileall -q teate scripts
ruff check teate scripts tests
```

実際のsandbox-runtimeを使う隔離テストは`TEATE_SANDBOX_INTEGRATION=1`で有効化します。
隔離を起動できないホストでは保留し、安全設定を弱めて通しません。
