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

| Aspect | BEAR.Sunday | Laravel | Symfony | WordPress |
|--------|-------------|---------|---------|-----------|
| **Taint Tracking** | Psalm + type-enforced | Partial | Partial | None |
| **Value/Representation** | Separated (enforced) | Mixed | Mixed | Mixed |
| **Escaping** | Explicit (Qiq) | Implicit (Blade) | Implicit (Twig) | Manual |
| **Global State** | None | Minimal | Minimal | Everywhere |
| **AI Comprehension** | High | Medium | Medium-High | Low |

---

## vs WordPress

WordPress represents the opposite end of the spectrum: maximum freedom, minimum constraints.

### Global State

```php
// WordPress: Global state everywhere
function get_user_data() {
    global $wpdb, $current_user;
    $id = $_GET['id'];  // Direct superglobal access
    return $wpdb->get_row("SELECT * FROM users WHERE id = $id");  // SQL injection
}

// BEAR.Sunday: No global state possible
class User extends ResourceObject
{
    public function __construct(
        private QueryInterface $query  // Injected, testable
    ) {}

    public function onGet(int $id): static  // Type-enforced, no injection
    {
        $this->body = $this->query->find($id);
        return $this;
    }
}
```

### Escaping

```php
// WordPress: Must remember to escape, easy to forget
echo '<div>' . $user_input . '</div>';           // XSS
echo '<div>' . esc_html($user_input) . '</div>'; // Safe, but manual

// BEAR.Sunday + Qiq: Must explicitly choose
{{h $userInput }}  // Cannot output without choosing escape method
```

### Security Implications

| Aspect | WordPress | BEAR.Sunday |
|--------|-----------|-------------|
| SQL Injection | Very common | Structurally prevented |
| XSS | Common (manual escape) | Renderer boundary + explicit escape |
| Dependency audit | Difficult (globals) | Easy (constructor) |
| AI analysis | Nearly impossible | Straightforward |

**WordPress philosophy:** "Trust the developer"
**BEAR.Sunday philosophy:** "Constrain the developer"

---

## vs Laravel

Laravel provides excellent security tools, but allows bypassing them.

### Hidden Dependencies

```php
// Laravel: Facades hide what's happening
class UserController extends Controller
{
    public function store(Request $request)
    {
        $user = User::create($request->all());  // Mass assignment risk
        Cache::put('user', $user);              // Where does Cache come from?
        Log::info('User created');              // Where does Log come from?
        return view('user.show', compact('user'));
    }
}

// BEAR.Sunday: Everything is visible
class User extends ResourceObject
{
    public function __construct(
        private UserRepository $repo,
        private CacheInterface $cache,  // Visible
        private LoggerInterface $log    // Visible
    ) {}

    public function onPost(
        #[Valid] UserInput $input  // Validated, typed
    ): static {
        $this->body = $this->repo->create($input);
        return $this;
    }
}
```

### Escaping Bypass

```php
// Laravel Blade: Easy to bypass auto-escaping
{{ $safe }}           // Escaped
{!! $dangerous !!}    // Raw output - XSS if misused

// Qiq: No "raw" shortcut, must be intentional
{{h $safe }}          // HTML escaped
{{= $raw }}           // Raw, but "=" makes intent clear
```

### Mass Assignment

```php
// Laravel: $fillable/$guarded can be forgotten
class User extends Model
{
    // If $fillable is missing, all fields are assignable
    // $request->all() can include 'is_admin' => true
}

// BEAR.Sunday: No ORM magic, explicit mapping required
public function onPost(UserInput $input): static
{
    // Only properties defined in UserInput are accepted
}
```

### Security Implications

| Aspect | Laravel | BEAR.Sunday |
|--------|---------|-------------|
| Dependency visibility | Hidden (Facades) | Explicit (DI) |
| Mass assignment | Possible if misconfigured | Impossible (no magic) |
| Escape bypass | Easy (`{!! !!}`) | Intentional only |
| Testing | Requires mocking facades | Natural (DI) |

**Laravel philosophy:** "Provide safe defaults, allow escape hatches"
**BEAR.Sunday philosophy:** "No escape hatches by design"

---

## vs Symfony

Symfony is the closest to BEAR.Sunday in explicitness, but differs in representation handling.

### Representation Boundary

```php
// Symfony: Controller returns Response (HTML/JSON)
class UserController extends AbstractController
{
    #[Route('/user/{id}')]
    public function show(int $id): Response
    {
        $user = $this->userRepository->find($id);

        // Option 1: Twig (safe, but controller chooses representation)
        return $this->render('user/show.html.twig', ['user' => $user]);

        // Option 2: Direct Response (XSS possible)
        return new Response("<h1>{$user->getName()}</h1>");
    }
}

// BEAR.Sunday: Resource returns value only
class User extends ResourceObject
{
    public function onGet(int $id): static
    {
        $this->body = $this->repo->find($id);
        return $this;
        // Representation is NEVER chosen here
        // Renderer handles HTML/JSON/XML based on content negotiation
    }
}
```

### Content Negotiation

```php
// Symfony: Must implement manually or use FOSRestBundle
#[Route('/api/user/{id}')]
public function show(int $id): Response
{
    $user = $this->repo->find($id);
    if ($request->getPreferredFormat() === 'json') {
        return $this->json($user);
    }
    return $this->render('user.html.twig', ['user' => $user]);
}

// BEAR.Sunday: Built-in, automatic
// Same resource serves HTML, JSON, XML based on Accept header
// Security is consistent across all representations
```

### Security Implications

| Aspect | Symfony | BEAR.Sunday |
|--------|---------|-------------|
| Value/Representation | Convention (can mix) | Enforced (cannot mix) |
| Content negotiation | Manual/Bundle | Built-in |
| Escape bypass | Possible (raw Response) | Impossible |
| Security consistency | Per-representation | Architectural |

**Symfony philosophy:** "Explicit configuration, flexible output"
**BEAR.Sunday philosophy:** "Explicit configuration, constrained output"

---

## Summary: The Constraint Spectrum

```
← More Freedom                              More Constraints →

WordPress    Slim    Laravel    Symfony    BEAR.Sunday
    │         │         │          │            │
    ▼         ▼         ▼          ▼            ▼
 Globals   No rules  Facades   Explicit    Enforced
 No types  Freedom   Magic     DI          Boundaries
 Manual    Manual    Auto      Auto        Explicit
 escape    escape    escape    escape      escape
```

The further right, the harder it is to write insecure code.

BEAR.Sunday trades flexibility for security guarantees.

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
