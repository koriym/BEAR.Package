# Security through Architecture

BEAR.Sunday does not merely provide security tools. It enforces security through architectural constraints.

Traditional frameworks offer developers safe methods and hope they will be used correctly. BEAR.Sunday takes a different approach: it makes unsafe patterns structurally impossible to write.

---

## The Four Pillars

### 1. Taint-Aware Architecture

Every input in BEAR.Sunday passes through a typed resource boundary. When a request arrives, parameters are automatically cast to their declared types before reaching application code.

```php
public function onGet(int $id, string $name): static
{
    // $id is guaranteed to be an integer
    // No SQL injection possible through numeric ID
}
```

This type enforcement integrates naturally with Psalm's taint analysis. Psalm can track data flow from input to output, catching injection vulnerabilities at compile time rather than runtime.

### 2. Value and Representation Separation

A BEAR.Sunday resource cannot return HTML. It can only return values. The transformation of values into HTML, JSON, or any other format happens in a separate Renderer layer that the resource has no control over.

```php
public function onGet(): static
{
    $this->body = ['name' => $userInput];  // Value only
    return $this;
}
```

The Renderer then handles escaping according to the output format. This architectural boundary makes XSS vulnerabilities structurally difficult. A developer cannot accidentally echo raw HTML because there is nowhere in a resource to echo anything.

### 3. Explicit over Implicit

BEAR.Sunday uses Qiq for templating, which requires explicit escaping for every output. Unlike Twig or Blade where auto-escaping happens silently, Qiq forces developers to consciously choose their escape context.

```php
{{h $userName }}   // HTML context
{{u $redirectUrl }} // URL context
{{j $jsonData }}   // JavaScript context
```

This explicitness extends to dependency injection. Every dependency appears in the constructor. There are no facades, no service locators, no magic methods hiding what a class actually uses. When you read a BEAR.Sunday class, you see everything it depends on.

### 4. AI-Friendly Architecture

Because BEAR.Sunday code follows a uniform structure with no hidden behaviors, AI security analysis becomes significantly more effective. The AI can read a resource class and understand exactly what it does—there are no layers of abstraction to trace through, no magic to decode.

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

Security is not bolted on. It is built in.
