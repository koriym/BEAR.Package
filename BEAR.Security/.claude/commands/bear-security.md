# BEAR.Security Development Context

CONTEXT.md を読んで、この会話の文脈を引き継いでください。

## 言語設定
- 会話: 日本語
- ドキュメント: 英語
- コード/コミット: 英語

## 核心的な哲学

**Writability vs Readability**
- 他のFW: 書きやすさ優先（Facades, Magic Methods）
- BEAR.Sunday: 読みやすさ優先（制約、明示性）
- セキュリティは「読む」作業 → 読みやすさ = セキュリティ

## BEAR.Sundayの強み（3行）

1. **入力は型、出力は構造** — `int $id` で受け取り、`ResourceObject` で返す
2. **全てが明示的** — Pure DI、明示的エスケープ、隠れた挙動なし
3. **型が証明する** — PHPStan/Psalm maxで検証済み

## 主要コマンド

```bash
composer security-scan   # SAST
composer security-audit  # AI分析
composer security        # 両方
composer tests           # テスト実行
```

## 参照ドキュメント

- docs/security-architecture.md - セキュリティアーキテクチャ
- docs/comparison-enterprise.md - 競合比較
- CONTEXT.md - 詳細な開発コンテキスト
