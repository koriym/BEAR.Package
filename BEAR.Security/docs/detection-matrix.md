# BEAR.Security 検出対応表

## 概要

BEAR.Security の検出能力を整理したドキュメントです。

- **SAST**: 14 Detectors
- **DAST**: HTTP-based testing
- **AI Auditor**: Claude API連携
- **Psalm Taint**: データフロー追跡（外部連携）
- **Composer Audit**: 依存関係脆弱性（外部連携）

---

## OWASP Top 10 (2021) 対応表

| ID | カテゴリ | SAST | DAST | AI | 状態 |
|----|----------|:----:|:----:|:--:|:----:|
| A01 | Broken Access Control | ✓ | ✓ | ✓ | **対応** |
| A02 | Cryptographic Failures | ✓ | - | ✓ | **対応** |
| A03 | Injection | ✓ | ✓ | ✓ | **対応** |
| A04 | Insecure Design | - | - | ✓ | AI専用 |
| A05 | Security Misconfiguration | ✓ | ✓ | ✓ | **対応** |
| A06 | Vulnerable Components | - | - | - | composer audit |
| A07 | Auth Failures | ✓ | ✓ | ✓ | **対応** |
| A08 | Integrity Failures | ✓ | - | ✓ | **対応** |
| A09 | Logging Failures | - | - | ✓ | AI専用 |
| A10 | SSRF | ✓ | ✓ | ✓ | **対応** |

---

## SAST Detectors (14個)

### 検出可能な脆弱性

| Detector | CWE | 脆弱性 | パターン例 |
|----------|-----|--------|-----------|
| SqlInjectionDetector | CWE-89 | SQLインジェクション | `query("SELECT * FROM users WHERE id = " . $id)` |
| XssDetector | CWE-79 | クロスサイトスクリプティング | `echo $_GET['name']` |
| CommandInjectionDetector | CWE-78 | OSコマンドインジェクション | `shell_exec('ls ' . $dir)` |
| PathTraversalDetector | CWE-22 | パストラバーサル | `file_get_contents('/data/' . $_GET['file'])` |
| RemoteFileInclusionDetector | CWE-98, CWE-918 | RFI/SSRF | `file_get_contents($_POST['url'])` |
| CsrfDetector | CWE-352 | CSRF | フォームにトークンなし |
| CryptographicFailuresDetector | CWE-327, CWE-259 | 弱い暗号化、ハードコード秘密鍵 | `md5($password)`, `$apiKey = 'sk_live_...'` |
| InsecureDeserializationDetector | CWE-502 | 安全でないデシリアライズ | `unserialize($_POST['data'])` |
| DangerousFunctionDetector | CWE-94 | 危険な関数 | `eval($code)`, `assert($expr)` |
| SessionSecurityDetector | CWE-384 | セッション固定 | `$_SESSION['user'] = $id` (regenerate_idなし) |
| OpenRedirectDetector | CWE-601 | オープンリダイレクト | `header('Location: ' . $_GET['url'])` |
| XxeDetector | CWE-611 | XXE | `simplexml_load_string($_POST['xml'])` |
| HeaderInjectionDetector | CWE-113 | HTTPヘッダーインジェクション | `header('Set-Cookie: ' . $_GET['v'])` |
| WeakRandomDetector | CWE-330 | 弱い乱数 | `$token = md5(time())` |

---

## AI Auditor 専用検出

SASTでは検出困難、AIの文脈理解が必要な脆弱性：

| 脆弱性 | CWE | 検出アプローチ |
|--------|-----|---------------|
| IDOR (認可バイパス) | CWE-639 | 認可チェックの欠如を文脈から判断 |
| Mass Assignment | CWE-915 | 動的フィールド更新の権限昇格リスク |
| Race Condition (TOCTOU) | CWE-367 | 並行実行の問題を理解 |
| Timing Attack | CWE-208 | `===` vs `hash_equals()` の違い |
| Business Logic Flaw | CWE-840 | ビジネスロジックの欠陥 |
| Log Injection | CWE-117 | ログへの不正データ挿入 |
| ReDoS | CWE-1333 | 正規表現の複雑性分析 |

---

## DAST 検出対応

| 脆弱性 | Payload | 検出方法 |
|--------|---------|----------|
| SQL Injection | `' OR '1'='1`, `1; DROP TABLE` | エラー応答、遅延 |
| XSS (Reflected) | `<script>alert(1)</script>` | 反射確認 |
| Command Injection | `; ls -la`, `| cat /etc/passwd` | 応答内容確認 |
| Path Traversal | `../../../etc/passwd` | ファイル内容確認 |
| CSRF | トークンなしPOST | 成功可否 |
| Open Redirect | `//evil.com` | リダイレクト先確認 |

---

## 検出範囲外（他ツール推奨）

| 脆弱性カテゴリ | 推奨ツール |
|---------------|-----------|
| 依存関係CVE | `composer audit`, Snyk, Dependabot |
| コンテナ脆弱性 | Trivy, Grype |
| インフラ設定 | Checkov, tfsec |
| ネットワーク | OpenVAS, Nessus |
| API仕様違反 | OWASP ZAP, Burp Suite |
| Secrets in Git | gitleaks, truffleHog |

---

## CI/CD セキュリティゲート判定基準

### Fail条件（推奨）

| 重大度 | 閾値 | アクション |
|--------|------|-----------|
| CRITICAL | 1件以上 | ビルド失敗 |
| HIGH | 3件以上 | ビルド失敗 |
| MEDIUM | 10件以上 | 警告 |
| LOW | 制限なし | 情報のみ |

### GitHub Actions 設定例

```yaml
- name: SAST Scan
  run: vendor/bin/bear.security-scan src --format=sarif > sast.sarif

- name: AI Audit (リリース時のみ)
  if: github.event_name == 'release'
  env:
    ANTHROPIC_API_KEY: ${{ secrets.ANTHROPIC_API_KEY }}
  run: vendor/bin/bear-security-audit src --format=sarif > ai-audit.sarif
```

---

## 比較: BEAR.Security vs 他ツール

| 機能 | BEAR.Security | VADDY | ZAP | PHPStan |
|------|:-------------:|:-----:|:---:|:-------:|
| SAST (静的解析) | ✓ | - | - | ✓ |
| DAST (動的テスト) | ✓ | ✓ | ✓ | - |
| AI分析 | ✓ | - | - | - |
| Psalm Taint連携 | ✓ | - | - | - |
| OWASP Top 10 100% | ✓ | △ | ✓ | △ |
| SARIF出力 | ✓ | - | ✓ | ✓ |
| OSS/無料 | ✓ | - | ✓ | ✓ |
| BEAR.Sunday最適化 | ✓ | - | - | - |

---

## 誤検知回避ルール

AIが安全と判断するパターン：

| パターン | 安全な理由 |
|----------|-----------|
| `$pdo->prepare()` + `execute([$var])` | パラメータバインディング |
| `$pdo->exec()` (DDL) | shell_execではない |
| `escapeshellarg()` + ホワイトリスト | 入力検証済み |
| `basename()` + 固定ベースパス | パストラバーサル防止 |
| `md5()` for cache key | セキュリティ用途ではない |
| `YOUR_API_KEY_HERE` | プレースホルダー |

---

## 今後の拡張予定

- [ ] Bedrock Auditor (AWS環境向け)
- [ ] Ollama Auditor (ローカルLLM)
- [ ] GraphQL脆弱性検出
- [ ] WebSocket脆弱性検出
- [ ] カスタムルールYAML定義
