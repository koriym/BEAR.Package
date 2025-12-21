# Security through Architecture

BEAR.Sunday provides security through architectural constraints, not just security tools.

## Philosophy

| Approach | Description |
|----------|-------------|
| **Traditional** | "Provide tools" → Safe if used correctly |
| **BEAR.Sunday** | "Enforce constraints" → Unsafe patterns are impossible |

---

## Four Pillars

### 1. Taint-Aware Architecture

BEAR.Sunday's type-enforced input handling integrates naturally with taint analysis.

```php
// Input is type-enforced at the resource boundary
public function onGet(int $id, string $name): static
{
    // $id is guaranteed to be integer (sanitized)
    // $name is typed but may still be tainted for output
}
```

**Psalm Taint Analysis Integration:**

```bash
vendor/bin/psalm --taint-analysis
```

Psalm can track tainted data from resource input through to output, catching injection vulnerabilities at compile time.

### 2. Value / Representation Separation

Resources return **values only**. Representation (HTML, JSON) is handled by a separate Renderer layer.

```
Resource (Value)          Renderer (Representation)
      │                          │
      ▼                          ▼
$this->body = $data;  →   Renderer converts to HTML/JSON
      │                          │
      └── Security boundary ─────┘
```

**Why this matters:**

```php
// BEAR.Sunday: Cannot return HTML from resource
public function onGet(): static
{
    $this->body = ['name' => $userInput];  // Value only
    return $this;
}
// Renderer handles escaping

// Other frameworks: Controller can return raw HTML
return new Response("<div>{$userInput}</div>");  // XSS possible
```

The architectural separation makes XSS vulnerabilities structurally difficult.

### 3. Explicit over Implicit

#### Qiq: Explicit Escaping

Unlike Twig's automatic escaping, Qiq requires explicit context-aware escaping:

```php
// Twig: Implicit (auto-escape, easy to forget context)
{{ user.name }}              // Auto-escaped
{{ user.bio | raw }}         // Bypass available

// Qiq: Explicit (must choose escape context)
{{h $user->name }}           // h = HTML escape
{{u $url }}                  // u = URL escape
{{j $data }}                 // j = JavaScript escape
```

**Security benefit:** Developers must consciously consider the output context every time.

#### DI: Explicit Dependencies

All dependencies are visible in constructors:

```php
public function __construct(
    private UserRepository $repo,
    private Logger $logger,
    private AuthService $auth
) {}
// Every dependency is auditable
```

No hidden service location. No facades. No magic.

### 4. AI-Friendly Architecture

BEAR.Sunday's uniform, explicit structure enables more effective AI-powered security analysis.

**Why AI understands BEAR.Sunday better:**

| Aspect | BEAR.Sunday | Traditional Frameworks |
|--------|-------------|----------------------|
| Structure | Uniform ResourceObject | Various patterns |
| Hidden behavior | None (explicit DI) | Facades, Magic Methods |
| Input/Output | Typed args → $body | Various patterns |
| Dependencies | All in constructor | Service locator, etc. |

**Example:**

```php
// BEAR.Sunday: AI reads this and understands everything
class User extends ResourceObject
{
    public function __construct(
        private UserRepository $repo  // Dependency visible
    ) {}

    public function onGet(int $id): static  // Input clear
    {
        $this->body = $this->repo->find($id);  // Output clear
        return $this;
    }
}

// Laravel: AI must trace through layers
class UserController extends Controller
{
    public function show($id)  // No type
    {
        $user = User::find($id);  // Eloquent magic
        return view('user', compact('user'));  // What's passed?
    }
}
```

**Result:** AI security analysis is more accurate with less false positives on BEAR.Sunday code.

---

## Framework Comparison

| Aspect | BEAR.Sunday | Laravel | Symfony | Slim |
|--------|-------------|---------|---------|------|
| **Taint Tracking** | Psalm integration, type-enforced | Partial | Partial | None |
| **Value/Representation Separation** | Enforced (ResourceObject) | Convention | Convention | None |
| **Escaping** | Explicit (Qiq) | Implicit (Blade) | Implicit (Twig) | Manual |
| **AI Comprehension** | High (uniform structure) | Medium (magic) | Medium-High | Low (no structure) |
| **Unsafe Code** | Difficult to write | Possible | Possible | Easy |

### Detailed Comparison

#### Laravel

- **Strengths:** Rich security features (CSRF, auth, validation)
- **Weakness:** Facades hide dependencies, Eloquent magic, `{!! !!}` bypass
- **Philosophy:** "Provide safe tools" - developer discipline required

#### Symfony

- **Strengths:** Explicit DI, Security Voters, mature ecosystem
- **Weakness:** Controller returns Response directly, Twig auto-escape bypass
- **Philosophy:** "Explicit configuration" - but representation not separated

#### Slim

- **Strengths:** Minimal, PSR-15 compliant
- **Weakness:** No structure enforced, each project different, no conventions
- **Philosophy:** "Freedom" - security entirely up to developer

#### BEAR.Sunday

- **Strengths:** Constraints enforce security, uniform structure, explicit everything
- **Weakness:** Smaller ecosystem, learning curve
- **Philosophy:** "Constraints as features" - unsafe patterns are architecturally impossible

---

## BEAR.Security Integration

BEAR.Sunday's architecture combined with BEAR.Security provides multi-layer defense:

```
┌─────────────────────────────────────────────────────────┐
│                    Security Layers                       │
├─────────────────────────────────────────────────────────┤
│  Layer 1: Architecture    │ Constraints prevent unsafe  │
│                           │ patterns at design level    │
├───────────────────────────┼─────────────────────────────┤
│  Layer 2: Psalm Taint     │ Data flow analysis at       │
│                           │ compile time                │
├───────────────────────────┼─────────────────────────────┤
│  Layer 3: BEAR.Security   │ 14 SAST detectors for       │
│           SAST            │ pattern-based detection     │
├───────────────────────────┼─────────────────────────────┤
│  Layer 4: BEAR.Security   │ Context-aware analysis      │
│           AI Auditor      │ for business logic flaws    │
└───────────────────────────┴─────────────────────────────┘
```

This combination provides enterprise-grade security without enterprise costs.

---

## Conclusion

BEAR.Sunday's security advantage is not about having more security features—it's about having an architecture where **insecure code is difficult to write**.

| Traditional Approach | BEAR.Sunday Approach |
|---------------------|---------------------|
| Add security tools | Design secure architecture |
| Train developers | Constrain possibilities |
| Review for mistakes | Prevent mistakes structurally |
| Hope for compliance | Enforce by design |

Security is not bolted on. It's built in.
