# Security through Architecture

BEAR.Sunday does not merely provide security tools. It enforces security through architectural constraints.

## Writability vs Readability

Most frameworks optimize for **writability**—making code easy to write. Facades, magic methods, and implicit behaviors reduce keystrokes and speed up development. The cost is paid later, when someone must understand, audit, or debug that code.

BEAR.Sunday optimizes for **readability**—making code easy to understand. Constraints and explicit patterns require more deliberate writing, but the result is code where what you read is what you get.

Security is fundamentally a **reading** activity:

- Understanding what code does
- Tracing data flow from input to output
- Auditing dependencies and access patterns
- Verifying that protections are in place

An architecture optimized for reading is an architecture optimized for security. When code is explicit, auditors can verify it. When dependencies are visible, they can be traced. When patterns are uniform, tools—both human and AI—can analyze them reliably.

BEAR.Sunday's constraints are not limitations. They are the foundation of security.

---

## Decisive Architectural Differences

### Thorough Static Analysis

BEAR.Sunday and its underlying libraries are analyzed with PHPStan and Psalm at maximum strictness levels. This means:

- All arrays have explicit shapes, not just `array` but `array{id: int, name: string}`
- The `mixed` type is minimized throughout the codebase
- Every function parameter and return type is explicitly declared

This level of type precision enables Psalm's taint analysis to work with maximum effectiveness. When types are vague, taint tracking becomes unreliable. When types are precise, the static analyzer can prove that tainted data never reaches dangerous functions.

### Input: Type Enforcement vs Request Object

The difference begins at input handling. In most frameworks, input arrives through a request object:

```php
// Laravel, Symfony, etc.
public function show(Request $request)
{
    $id = $request->get('id');  // Returns mixed - could be anything
    $id = $request->input('id'); // Same problem
}
```

The developer receives a value of unknown type and must validate it manually. In BEAR.Sunday, input is declared as typed method parameters:

```php
// BEAR.Sunday
public function onGet(int $id): static
{
    // $id is already an integer. Not a string, not null, not an array.
    // Type enforcement happened before this code runs.
}
```

This is not merely convenient—it eliminates entire vulnerability classes. SQL injection through numeric IDs becomes structurally impossible because non-numeric input never reaches the application code.

### Output: ResourceObject vs Arbitrary Response

In traditional frameworks, a controller can return anything:

```php
// Symfony
return new Response("<h1>$name</h1>");  // String
return $this->json($data);              // JSON
return $this->render('template.twig');  // HTML
return new BinaryFileResponse($path);   // File
```

The controller decides both what data to return and how to represent it. BEAR.Sunday separates these concerns:

```php
// BEAR.Sunday
public function onGet(): static
{
    $this->body = ['name' => $name];  // Always structured data
    return $this;                      // Always ResourceObject
}
```

A resource returns a ResourceObject with structured data in `$body`. How that data becomes HTML or JSON is decided elsewhere by the Renderer. The resource cannot output a raw string—there is no method for it.

### Schema: Optional vs Enforced

BEAR.Sunday can enforce input/output schemas using JsonSchema:

```php
#[JsonSchema('user.json')]
public function onGet(int $id): static
{
    $this->body = $this->repo->find($id);
    return $this;
    // Output is validated against schema before rendering
}
```

The schema defines what the resource accepts and returns. Invalid data triggers errors before reaching clients.

### Dependencies: Pure DI vs Service Location

Every dependency in BEAR.Sunday is injected through the constructor:

```php
class User extends ResourceObject
{
    public function __construct(
        private UserRepository $repo,
        private LoggerInterface $logger,
        private CacheInterface $cache
    ) {}
}
```

There are no facades, no service locators, no static calls to global containers. When you read a class, you see everything it uses. Security audits can trace dependencies without understanding framework internals.

The framework itself is built entirely with DI. Every framework component can be replaced by binding a different implementation. If a security vulnerability is discovered in a framework component, it can be swapped out without modifying application code.

This explicitness enables complete dependency visualization with [Ray.ObjectGrapher](https://github.com/ray-di/Ray.ObjectGrapher):

```php
$dot = (new ObjectGrapher)(new AppModule);
// Generates a GraphViz visualization of ALL dependencies
```

The entire application's dependency graph can be rendered as a diagram. Hidden dependencies cannot exist—if something is used, it appears in the graph. For security auditors, this provides verifiable proof that the application has no hidden service locations or undeclared dependencies.

BEAR.Sunday also logs which interceptors are applied to each ResourceObject. Security auditors can verify that authentication and authorization interceptors are correctly applied to protected resources, and identify any resources that may be missing required security checks.

---

## Why These Differences Matter for Security

### Taint Tracking

With typed parameters and structured output, Psalm's taint analysis works seamlessly. It can trace data from `int $id` through to `$this->body` and verify that tainted data never reaches dangerous functions.

### Escaping

BEAR.Sunday uses Qiq for templating, which requires explicit escaping context:

```php
{{h $userName }}   // HTML context
{{u $redirectUrl }} // URL context
{{j $jsonData }}   // JavaScript context
```

Unlike Twig or Blade where auto-escaping happens silently (and can be bypassed easily), Qiq forces conscious decisions about output context.

### AI Comprehension

Because BEAR.Sunday code follows uniform patterns with no hidden behaviors, AI security analysis becomes significantly more effective. The AI reads a resource class and understands exactly what it does—there are no layers of abstraction to trace through, no magic to decode.

---

## Framework Comparisons

### WordPress: The Opposite Extreme

WordPress represents maximum developer freedom. Any function can access global state. Any code can echo directly to the browser. There are no architectural constraints whatsoever.

```php
function get_user_data() {
    global $wpdb, $current_user;
    $id = $_GET['id'];
    return $wpdb->get_row("SELECT * FROM users WHERE id = $id");
}
```

This code has a SQL injection vulnerability that is immediately obvious. Yet WordPress allows it because WordPress trusts developers. The same logic in BEAR.Sunday would not compile—`$_GET['id']` cannot reach application code untyped, and concatenating variables into SQL requires explicit decisions that Psalm's taint analysis would flag.

WordPress provides escape functions like `esc_html()`, but developers must remember to use them every time. BEAR.Sunday's renderer boundary means there is no "every time"—escaping happens once, automatically, at the architectural layer.

The philosophies differ fundamentally. WordPress says "trust the developer." BEAR.Sunday says "constrain the developer."

### Laravel: The Convenience Trade-off

Laravel provides excellent security features. It has CSRF protection, authentication systems, input validation, and automatic output escaping in Blade templates. The problem is that all of these can be bypassed.

Consider this typical Laravel controller:

```php
class UserController extends Controller
{
    public function store(Request $request)
    {
        $user = User::create($request->all());
        Cache::put('user', $user);
        Log::info('User created');
        return view('user.show', compact('user'));
    }
}
```

Several security concerns hide in this innocent-looking code. Where do `Cache` and `Log` come from? They are facades—static calls that hide the actual dependencies. For security auditing, you cannot look at this class and know what it touches. You must understand Laravel's service container to trace the actual implementations.

The `$request->all()` call passes every submitted field to `User::create()`. If the developer forgot to define `$fillable` on the User model, this is a mass assignment vulnerability. An attacker could submit `is_admin=true` and escalate privileges.

In Blade templates, `{{ $var }}` auto-escapes but `{!! $var !!}` outputs raw HTML. The bypass is easy and tempting.

BEAR.Sunday makes different trade-offs. There are no facades—every dependency is visible in the constructor. There is no mass assignment—input binding is explicit. There is no raw output shortcut—Qiq's `{{= }}` syntax makes raw output intentional rather than convenient.

Laravel's philosophy is "provide safe defaults with escape hatches." BEAR.Sunday's philosophy is "no escape hatches."

### Symfony: Almost There

Symfony comes closest to BEAR.Sunday's explicitness. It uses proper dependency injection. It encourages typed parameters. Its security component is mature and well-designed.

The key difference is in representation handling. A Symfony controller returns a Response object:

```php
class UserController extends AbstractController
{
    public function show(int $id): Response
    {
        $user = $this->userRepository->find($id);
        return $this->render('user/show.html.twig', ['user' => $user]);
    }
}
```

The controller chooses both the data and its representation. It could just as easily return raw HTML:

```php
return new Response("<h1>{$user->getName()}</h1>");
```

This is perfectly valid Symfony code. The framework allows it. A BEAR.Sunday resource cannot make this choice—it returns values only, and the renderer layer handles representation separately.

Symfony's Twig templates auto-escape by default, but `{{ var|raw }}` bypasses this. The escape hatch exists because Symfony prioritizes flexibility.

For content negotiation, Symfony requires manual implementation or additional bundles. BEAR.Sunday provides it architecturally—the same resource automatically serves HTML, JSON, or XML based on the Accept header, with security consistent across all formats.

Symfony's philosophy is "explicit configuration with flexible output." BEAR.Sunday's philosophy is "explicit configuration with constrained output."

---

## The Constraint Spectrum

These frameworks exist on a spectrum from maximum freedom to maximum constraint:

```
← Freedom                                    Constraint →

WordPress    Slim    Laravel    Symfony    BEAR.Sunday
```

WordPress imposes almost no structure. Slim provides routing but no opinions on architecture. Laravel provides convenience with optional constraints. Symfony provides explicit structure with flexible output. BEAR.Sunday enforces constraints at every layer.

Moving right on this spectrum, it becomes progressively harder to write insecure code. BEAR.Sunday occupies the far right because it trades flexibility for security guarantees.

### Summary

| Aspect | WordPress | Laravel | Symfony | BEAR.Sunday |
|--------|-----------|---------|---------|-------------|
| Input handling | `$_GET` | `$request->all()` | `Request $request` | `int $id` |
| Output | `echo` | `Response` | `Response` | `ResourceObject` |
| Dependencies | Global | "Facades" | DI | Pure DI |
| Escaping | Manual | Auto + bypass | Auto + bypass | Explicit |
| Taint analysis | Impossible | Difficult | Difficult | Native |
| Security audit | Hard | Medium | Medium | Easy |

---

## BEAR.Security Integration

BEAR.Sunday's architecture creates a foundation for multi-layer security:

**Layer 1: Architecture** prevents unsafe patterns at design time. You cannot write XSS-vulnerable code because you cannot write HTML from a resource.

**Layer 2: Psalm Taint Analysis** tracks data flow at compile time. Tainted input that reaches dangerous functions triggers errors before deployment.

**Layer 3: BEAR.Security SAST** scans for 14 vulnerability patterns. It catches what architecture and static analysis might miss.

**Layer 4: BEAR.Security AI Auditor** performs context-aware analysis. It understands business logic and identifies vulnerabilities that pattern matching cannot detect.

This combination provides enterprise-grade security without enterprise costs.

---

## Conclusion

BEAR.Sunday's security advantage is not about having more security features. Laravel and Symfony have plenty of security features. The advantage is architectural: BEAR.Sunday makes insecure code difficult to write in the first place.

Traditional security relies on developer discipline—use the safe functions, remember to escape, configure the protections correctly. BEAR.Sunday relies on structural constraints—unsafe patterns simply do not fit the architecture.

The three pillars of BEAR.Sunday security:

1. **Typed input, structured output** — boundaries are enforced
2. **Everything explicit** — pure DI, explicit escaping, no hidden magic
3. **Types prove safety** — PHPStan/Psalm max level enables reliable taint analysis

Security is not bolted on. It is built in.
