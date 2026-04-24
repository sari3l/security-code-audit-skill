# Swift Security Checklist

Language-specific security checklist organized by C1-C12 categories. Covers Vapor services, Apple-platform apps, URLSession clients, WebKit usage, and CryptoKit / Keychain patterns.

---

## Language-Specific Hotspots

- Vapor `Content` binding into models and route groups without policy checks
- `NSPredicate(format:)`, shelling out with `Process`, and raw SQL adapters
- Secrets in `UserDefaults`, Info.plist, entitlements, or debug logs
- WebKit bridges, `loadHTMLString`, and app/web trust-boundary mistakes

---

## C1: Injection

### Key Questions
- Are SQL, `NSPredicate`, or command strings built with interpolation?
- Can user input reach `Process`, `NSTask`, raw SQL, or shell helpers?
- Are WebKit or HTML rendering APIs fed attacker-controlled markup?
- Are templates compiled from user input in server-side Swift?

### Dangerous Patterns

```swift
let sql = "SELECT * FROM users WHERE email = '\(email)'"
let predicate = NSPredicate(format: "name == '\(name)'")

let task = Process()
task.launchPath = "/bin/sh"
task.arguments = ["-c", "tar -xf \(archive)"]

webView.loadHTMLString(userHTML, baseURL: nil)
```

### Detection

```bash
grep -rn 'NSPredicate\\(format:|Process\\(|launchPath|sqlQuery|raw\\(' --include="*.swift"
grep -rn 'loadHTMLString|evaluateJavaScript|WKWebView' --include="*.swift"
grep -rn 'SELECT .*\\\\\\(|INSERT .*\\\\\\(|UPDATE .*\\\\\\(' --include="*.swift"
```

---

## C2: Authentication

### Key Questions
- Are tokens stored in Keychain instead of `UserDefaults`?
- Are JWTs or signed tokens validated with explicit algorithms and issuer checks?
- Are login, OTP, and device-binding flows rate-limited and short-lived?
- Is `LAContext` fallback behavior appropriate for sensitive actions?

### Detection

```bash
grep -rn 'UserDefaults|Keychain|SecItemAdd|SecItemCopyMatching|JWT|LAContext' --include="*.swift"
grep -rn 'otp|magic|resetPassword|authenticate|biometric' --include="*.swift"
```

---

## C3: Authorization

### Key Questions
- Are Vapor route groups protected with middleware before handler registration?
- Are objects fetched with ownership or tenant checks rather than just route IDs?
- Are feature flags or client-side role checks mistakenly treated as authorization?
- Are app extensions, URL schemes, and XPC interfaces validating caller identity?

### Detection

```bash
grep -rn 'grouped\\(|middleware|RoutesBuilder|req.parameters.get' --include="*.swift"
grep -rn 'isAdmin|role|ownerId|tenantId|userId' --include="*.swift"
grep -rn 'openURL|handle\\(|NSExtension|xpc' --include="*.swift"
```

---

## C4: Mass Assignment

### Key Questions
- Are `Codable` request bodies decoded directly into persistence models?
- Can privileged properties like `role`, `isAdmin`, `balance`, or `ownerID` be set by clients?
- Are PATCH handlers merging arbitrary dictionaries into domain objects?
- Are Core Data or Fluent updates scoped to a narrow DTO?

### Dangerous Patterns

```swift
final class User: Model, Content {
    @Field(key: "role") var role: String
    @Field(key: "is_admin") var isAdmin: Bool
}

let user = try req.content.decode(User.self)
try await user.save(on: req.db)
```

### Detection

```bash
grep -rn 'Content\\s*{|Codable|JSONDecoder\\(|decode\\(.*self\\)' --include="*.swift"
grep -rn 'role|isAdmin|ownerID|tenantID|balance|creditLimit' --include="*.swift"
```

---

## C5: Data Exposure

### Key Questions
- Are secrets embedded in Info.plist, source, build settings, or environment defaults?
- Do logs, crash reports, or debug overlays expose tokens or PII?
- Are sensitive files included in app bundles or server responses?
- Do models conform to `CustomStringConvertible` or `Codable` in ways that leak secrets?

### Detection

```bash
grep -rn 'API_KEY|SECRET|TOKEN|PASSWORD|PRIVATE KEY' --include="*.swift" --include="*.plist" --include="*.xcconfig"
grep -rn 'print\\(|Logger\\(|os_log|debugPrint' --include="*.swift"
grep -rn 'UserDefaults|URLCredential|Authorization' --include="*.swift"
```

---

## C6: Security Misconfiguration

### Key Questions
- Is App Transport Security relaxed broadly?
- Are entitlements, URL schemes, pasteboard, and file-sharing settings overly permissive?
- Are Vapor debug settings, stack traces, or auto-migrations exposed in production?
- Are cookies, CORS, and TLS settings configured safely on server-side Swift?

### Detection

```bash
grep -rn 'NSAppTransportSecurity|NSAllowsArbitraryLoads|UIFileSharingEnabled|LSSupportsOpeningDocumentsInPlace' --include="*.plist"
grep -rn 'isRelease|environment|autoMigrate|CORS|SameSite|secure' --include="*.swift"
```

---

## C7: XSS / Web Content Injection

### Key Questions
- Can `WKWebView` render attacker HTML or execute attacker JS?
- Are JavaScript bridges validating message origin and command set?
- Are server-rendered templates escaping user data by context?
- Are markdown or rich text flows sanitized before trust elevation?

### Detection

```bash
grep -rn 'WKScriptMessageHandler|evaluateJavaScript|loadHTMLString|javaScriptEnabled' --include="*.swift"
grep -rn 'Leaf|Stencil|Mustache|unsafeHTML|markdown' --include="*.swift"
```

---

## C8: Dependencies

### Review Checklist
- Review SwiftPM, CocoaPods, Carthage, and vendored binary frameworks.
- Check WebKit wrappers, markdown renderers, zip/image parsers, and auth libraries.
- Flag abandoned or unmaintained packages used in networking or crypto flows.
- Verify minimum iOS / macOS deployment targets still receive platform security fixes.

### Detection

```bash
find . -name "Package.swift" -o -name "Podfile" -o -name "Cartfile"
grep -rn 'package\\(|pod |github "' Package.swift Podfile Cartfile
```

---

## C9: Cryptography

### Key Questions
- Are secrets generated with `SecRandomCopyBytes`, not timestamps or UUIDs?
- Is CryptoKit used correctly, with nonces and keys managed outside source?
- Are tokens and signatures verified in constant time?
- Are keys stored in Keychain / Secure Enclave when applicable?

### Detection

```bash
grep -rn 'SecRandomCopyBytes|CryptoKit|HMAC|SHA256|AES\\.GCM|UUID\\(' --include="*.swift"
grep -rn 'UserDefaults.*token|hardcoded|privateKey|symmetricKey' --include="*.swift"
```

---

## C10: SSRF

### Key Questions
- Can untrusted URLs reach `URLSession`, `AsyncHTTPClient`, or webhook fetchers?
- Are redirects, localhost, metadata services, custom schemes, and DNS rebinding blocked?
- Are preview/import features validating hostnames after resolution?
- Are server-side Swift apps separating internal and external HTTP clients?

### Detection

```bash
grep -rn 'URLSession|URLRequest|HTTPClient|AsyncHTTPClient' --include="*.swift"
grep -rn '169\\.254\\.169\\.254|localhost|127\\.0\\.0\\.1|::1|followRedirects' --include="*.swift"
```

---

## C11: Logging & Monitoring

### Key Questions
- Are `Logger` / `OSLog` calls exposing secrets?
- Are privacy annotations used for sensitive values in structured logs?
- Are auth failures, permission denials, and key lifecycle events auditable?
- Do crash and analytics SDKs capture full request or credential context?

### Detection

```bash
grep -rn 'Logger\\(|OSLog|os_log|print\\(' --include="*.swift"
grep -rn 'privacy:|token|password|secret|authorization' --include="*.swift"
```

---

## C12: Platform & Deployment

### Key Questions
- Are entitlements minimal and hardened runtime / sandbox settings appropriate?
- Are CI secrets, signing keys, and provisioning profiles protected?
- Do containers or server processes run as non-root with separated secrets?
- Are app groups, keychain sharing, and local file access bounded to need?

### Detection

```bash
find . -name "*.entitlements" -o -name "Dockerfile" -o -name ".github" -o -name "*.mobileprovision"
grep -rn 'com.apple.security|keychain-access-groups|application-groups|USER root' --include="*.entitlements" --include="Dockerfile" --include="*.yml"
```
