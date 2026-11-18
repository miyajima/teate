# AIから使う最短手順

通常、Teate内部のLLM呼び出しは0回。呼び出し側のモデルは変更しない。

```bash
cd /path/to/teate
source .teate/env.sh
python3 -m teate agent cycle --scanner npm-audit --execute
python3 -m teate agent render
```

OSVに接続できる環境は最初から `--scanner osv`。失敗後の自動切替はしない。
検査だけなら `--execute` を外す。候補の作成までなら `--prepare`。
本番反映は事前登録された対象・パッケージ・テスト・デプロイ・復旧条件の範囲だけ。
未登録の対象をAIが自分で許可しない。

- JSON最大12KB。`facts` が正本。注目候補5件、未確認例2件まで。
- `execution` のrun ID・段階・理由・次の操作を使う。詳細は `history --run ID`。
- 中断やCI待ちは `agent resume --run ID`。操作結果が不明なら観測のみ行い、変更操作を再送しない。
- 終了0でも脆弱性ゼロとは限らない。1は部分検査・保留、2はエラー。
- 任意のモデル応答は、提示された `response_schema` のID選択だけ。件数・版・優先度・完了状態は生成しない。
- 未応答・不正・古い応答は `agent render` の定型報告へ戻す。再生成ループや上位モデルへの切替なし。
- 任意のCodex調査は既存のChatGPT認証を利用。1回だけ、既存の制限内で調査パッチを保存する。本番適用しない。

登録、フックの契約、状態遷移は[運用手順](operations.md)を参照。
