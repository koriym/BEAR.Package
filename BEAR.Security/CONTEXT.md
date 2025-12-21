# BEAR.Security Development Context

## Project Overview

BEAR.Security is a security scanner for BEAR.Sunday applications with:
- **SAST**: 14 pattern-based detectors
- **DAST**: Dynamic testing via HTTP workflows
- **AI Auditor**: Claude API integration for context-aware analysis
- **Output**: Console, JSON, SARIF (GitHub Security), HTML

## Key Documents Created

### docs/security-architecture.md
BEAR.Sundayのセキュリティ優位性を説明するドキュメント。

**核心的な哲学:**
- **Writability vs Readability**: 書きやすさ優先 vs 読みやすさ優先
- セキュリティは「読む」作業 → 読みやすいアーキテクチャ = セキュアなアーキテクチャ

**決定的な違い (Decisive Architectural Differences):**
1. **Thorough Static Analysis** - PHPStan/Psalm max, array shapes, minimal mixed
2. **Input: Type Enforcement** - `$request->get('id')` vs `int $id`
3. **Output: ResourceObject** - 任意のResponse vs 構造化された出力
4. **Schema: JsonSchema** - 入出力のスキーマ強制
5. **Dependencies: Pure DI** - Ray.ObjectGrapher で全依存可視化、インターセプターログ

**フレームワーク比較:**
- WordPress: グローバル状態、手動エスケープ（対極）
- Laravel: "Facades"（実際はStatic Proxy）、便利だがバイパス可能
- Symfony: 明示的DIだが表現層の分離なし
- BEAR.Sunday: 制約による安全

**3つの柱:**
1. Typed input, structured output — 境界が強制される
2. Everything explicit — Pure DI, 明示的エスケープ, 隠れた挙動なし
3. Types prove safety — PHPStan/Psalm maxでTaint分析が機能

### Other Documents
- `docs/comparison-enterprise.md` - Snyk/SonarQube/Checkmarx との比較
- `docs/comparison-vaddy.md` - VADDY SaaS との比較
- `docs/detection-matrix.md` - 検知能力マトリクス

## Composer Scripts

```bash
composer security-scan   # SAST (14 detectors)
composer security-audit  # AI分析 (ANTHROPIC_API_KEY required)
composer security        # 両方実行
```

## Architecture Insights

### BEAR.Sundayの強み（3行）
1. **入力は型、出力は構造** — `int $id` で受け取り、`ResourceObject` で返す
2. **全てが明示的** — Pure DI、明示的エスケープ、隠れた挙動なし
3. **型が証明する** — PHPStan/Psalm maxで検証済み、Taint分析が確実に機能

### AIにとってBEAR.Sundayが理解しやすい理由
- 構造の均一性（ResourceObject統一）
- 隠れた挙動なし（DIで明示）
- 入出力の明確さ（型付き引数 → $body）
- 依存の可視性（コンストラクタに全て）

### 値と表現の分離
- Symfony: Controller → Response (HTML/JSON を直接返す)
- BEAR.Sunday: Resource → $body (値のみ) → Renderer → Response

### 明示的エスケープ (Qiq)
- Twig: 暗黙的（自動エスケープ、`|raw` でバイパス）
- Qiq: 明示的（`{{h }}`, `{{u }}`, `{{j }}`）→ コンテキストを意識

## Current State

- Branch: `claude/vulnerability-scanning-tool-YFNUx`
- All tests passing
- Documentation complete
- Ready for review

## Language Preferences

- **会話**: 日本語
- **ドキュメント**: 英語
- **コード/コミット**: 英語
