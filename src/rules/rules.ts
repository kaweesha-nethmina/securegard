import { Severity, FindingCategory } from "../types";

export interface Rule {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  cwe: string[];
  owasp?: string;
  category: FindingCategory;
  languages: string[]; // file extensions this rule applies to, or "*"
  pattern: RegExp;
  remediation: string;
  /** Optional: if provided, a match is only flagged when this negative-lookaround style check does NOT also match the same line (reduces obvious false positives) */
  excludeIfMatches?: RegExp;
}

const JS_TS = ["js", "jsx", "ts", "tsx", "mjs", "cjs"];
const PY = ["py"];
const JAVA = ["java"];
const GO = ["go"];
const PHP = ["php"];
const RUBY = ["rb"];
const CSHARP = ["cs"];
const ANY = ["*"];

export const RULES: Rule[] = [
  // ---------------- INJECTION ----------------
  {
    id: "sg-sql-injection-concat",
    title: "SQL Injection via string concatenation",
    description:
      "A SQL query appears to be built by concatenating or interpolating untrusted input directly into the query string, instead of using parameterized queries or an ORM. This can allow an attacker to alter query logic (CWE-89).",
    severity: "critical",
    cwe: ["CWE-89"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: [...JS_TS, ...PY, ...JAVA, ...PHP, ...RUBY, ...CSHARP],
    pattern:
      /(SELECT|INSERT|UPDATE|DELETE|DROP)\s[^;'"]*(\+|\$\{|%s|f["'])[^;]*(FROM|INTO|WHERE|VALUES)?/i,
    remediation:
      "Use parameterized queries / prepared statements (e.g. `db.query('... WHERE id = ?', [id])`) or an ORM's safe query builder instead of concatenating input into SQL text.",
  },
  {
    id: "sg-command-injection",
    title: "OS Command Injection",
    description:
      "User-influenced data appears to be passed into a shell command execution function. If the input isn't strictly validated, an attacker can inject additional shell commands (CWE-78).",
    severity: "critical",
    cwe: ["CWE-78"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: [...JS_TS, ...PY, ...JAVA, ...GO, ...PHP, ...RUBY],
    pattern:
      /(child_process\.exec\(|exec\(|execSync\(|os\.system\(|subprocess\.(call|run|Popen)\(.*shell\s*=\s*True|Runtime\.getRuntime\(\)\.exec\(|popen\(|shell_exec\(|\`.*\$\{.*\}.*\`)/,
    remediation:
      "Avoid shell interpreters entirely: use the argv-array form of process spawning (e.g. `execFile`/`spawn` with an args array, or `subprocess.run([...], shell=False)`), and allow-list input.",
  },
  {
    id: "sg-nosql-injection",
    title: "NoSQL Injection",
    description:
      "Untrusted input is passed directly into a MongoDB-style query object/operator ($where, $ne, $gt), which can let an attacker manipulate query logic (CWE-943).",
    severity: "high",
    cwe: ["CWE-943"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: JS_TS,
    pattern: /\$where\s*:\s*.*req\.(body|query|params)|find\(\s*\{\s*.*req\.(body|query|params)/,
    remediation:
      "Validate and whitelist expected fields/types before building the query object; never pass raw `req.body`/`req.query` as (or into) a Mongo query filter.",
  },
  {
    id: "sg-ldap-injection",
    title: "LDAP Injection",
    description:
      "User input appears to be concatenated directly into an LDAP search filter (CWE-90).",
    severity: "high",
    cwe: ["CWE-90"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: [...JAVA, ...JS_TS, ...PY],
    pattern: /search(Filter)?\s*=\s*["'`].*\(\s*\w+\s*=\s*["'`]?\s*\+/,
    remediation: "Escape special LDAP filter characters or use a library that parameterizes LDAP filters.",
  },

  // ---------------- XSS ----------------
  {
    id: "sg-xss-innerhtml",
    title: "Cross-Site Scripting (XSS) via innerHTML",
    description:
      "Untrusted data is assigned to `innerHTML`/`outerHTML` (or React's `dangerouslySetInnerHTML`), which can execute attacker-controlled markup/script in the victim's browser (CWE-79).",
    severity: "high",
    cwe: ["CWE-79"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: JS_TS,
    pattern: /(\.innerHTML|\.outerHTML)\s*=\s*(?!["'`]\s*["'`])|dangerouslySetInnerHTML\s*=\s*\{\{/,
    remediation:
      "Use `textContent` for plain text, or sanitize HTML with a vetted library (e.g. DOMPurify) before rendering, and avoid `dangerouslySetInnerHTML` with unsanitized input.",
  },
  {
    id: "sg-xss-document-write",
    title: "Cross-Site Scripting via document.write",
    description: "`document.write`/`document.writeln` with dynamic input can inject executable markup (CWE-79).",
    severity: "medium",
    cwe: ["CWE-79"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: JS_TS,
    pattern: /document\.write(ln)?\s*\(/,
    remediation: "Avoid `document.write`; render content via safe DOM APIs or a templating engine with auto-escaping.",
  },
  {
    id: "sg-flask-autoescape-off",
    title: "Server-side template auto-escaping disabled",
    description: "Template auto-escaping has been explicitly turned off, re-enabling XSS in rendered templates (CWE-79).",
    severity: "high",
    cwe: ["CWE-79"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: PY,
    pattern: /autoescape\s*=\s*False/,
    remediation: "Keep auto-escaping enabled; use explicit `|safe`/`Markup` only for content you fully control and have sanitized.",
  },

  // ---------------- INSECURE CRYPTO / RANDOM ----------------
  {
    id: "sg-weak-hash",
    title: "Use of broken/weak hash algorithm",
    description:
      "MD5 or SHA-1 is used, which are cryptographically broken for security purposes (password hashing, integrity, signatures) (CWE-327).",
    severity: "medium",
    cwe: ["CWE-327", "CWE-328"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    languages: ANY,
    pattern: /\b(md5|sha1)\s*\(|createHash\(\s*["'](md5|sha1)["']|MessageDigest\.getInstance\(\s*["'](MD5|SHA1|SHA-1)["']/i,
    remediation: "Use SHA-256/SHA-3 for integrity checks, and a dedicated password-hashing function (bcrypt, scrypt, Argon2) for credentials — never a general-purpose hash.",
  },
  {
    id: "sg-weak-cipher-des",
    title: "Use of broken symmetric cipher (DES/RC4)",
    description: "DES and RC4 are considered broken and should not be used for new encryption (CWE-327).",
    severity: "high",
    cwe: ["CWE-327"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    languages: ANY,
    pattern: /\b(DES|RC4|Cipher\.getInstance\(\s*["']DES)/,
    remediation: "Use AES-256-GCM (or another modern AEAD cipher) instead.",
  },
  {
    id: "sg-insecure-random",
    title: "Insecure randomness used in a security-sensitive context",
    description:
      "`Math.random()` (or `random`/`rand`) is not cryptographically secure and is predictable. Using it for tokens, passwords, or keys allows attackers to guess values (CWE-338).",
    severity: "medium",
    cwe: ["CWE-338"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    languages: ANY,
    pattern: /(Math\.random\(\)|random\.random\(\)|rand\(\))\s*.{0,40}(token|password|secret|key|session|csrf|otp)/i,
    remediation: "Use a CSPRNG: `crypto.randomBytes`/`crypto.getRandomValues` (JS), `secrets` module (Python), or `SecureRandom` (Java).",
  },

  // ---------------- SECRETS ----------------
  {
    id: "sg-hardcoded-secret-generic",
    title: "Hardcoded credential or API key",
    description:
      "A string literal assigned to a variable named like a secret (password, api_key, token, secret) appears to be hardcoded in source (CWE-798).",
    severity: "critical",
    cwe: ["CWE-798"],
    owasp: "A07:2021 - Identification and Authentication Failures",
    category: "secret",
    languages: ANY,
    pattern:
      /\b(api[_-]?key|apikey|secret|password|passwd|pwd|token|access[_-]?key)\s*[:=]\s*["'`][A-Za-z0-9_\-\/+=]{8,}["'`]/i,
    excludeIfMatches: /(process\.env|os\.environ|getenv|System\.getenv|ENV\[|<%=|\{\{|import\.meta\.env|example|placeholder|xxx|changeme|your[_-]?)/i,
    remediation: "Move the secret to an environment variable or a secrets manager (Vault, AWS Secrets Manager, etc.) and rotate the exposed credential immediately.",
  },
  {
    id: "sg-aws-access-key",
    title: "AWS Access Key ID exposed",
    description: "A string matching the AWS Access Key ID format (AKIA...) is present in source (CWE-798).",
    severity: "critical",
    cwe: ["CWE-798"],
    owasp: "A07:2021 - Identification and Authentication Failures",
    category: "secret",
    languages: ANY,
    pattern: /\b(AKIA|ASIA)[0-9A-Z]{16}\b/,
    remediation: "Revoke this key in the AWS console immediately, then load credentials via environment variables or an IAM role instead of source code.",
  },
  {
    id: "sg-private-key-block",
    title: "Private key committed to source",
    description: "A PEM-format private key block is present in the file (CWE-798).",
    severity: "critical",
    cwe: ["CWE-798", "CWE-321"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "secret",
    languages: ANY,
    pattern: /-----BEGIN (RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/,
    remediation: "Remove the key from version control, rotate it, and load it from a secure secrets store or mounted file outside the repo.",
  },
  {
    id: "sg-slack-webhook",
    title: "Slack Webhook URL exposed",
    description: "A Slack incoming-webhook URL, which allows posting to a channel without further auth, is hardcoded (CWE-798).",
    severity: "high",
    cwe: ["CWE-798"],
    category: "secret",
    languages: ANY,
    pattern: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9\/]+/,
    remediation: "Revoke and regenerate the webhook, then load it from an environment variable.",
  },

  // ---------------- DANGEROUS EVAL / DESERIALIZATION ----------------
  {
    id: "sg-eval-usage",
    title: "Use of eval() / dynamic code execution",
    description:
      "`eval`, `new Function(...)`, or an equivalent dynamic-code-execution construct is used. If any part of the evaluated string is influenced by user input, this is full remote code execution (CWE-95).",
    severity: "high",
    cwe: ["CWE-95"],
    owasp: "A03:2021 - Injection",
    category: "sast",
    languages: [...JS_TS, ...PY, ...PHP, ...RUBY],
    pattern: /\beval\s*\(|new\s+Function\s*\(|\bexec\s*\(\s*["'`]?.*\+|Kernel\.eval\(/,
    remediation: "Avoid `eval`/dynamic execution entirely; use JSON.parse for data, or an explicit safe interpreter/allow-list for the specific operations needed.",
  },
  {
    id: "sg-insecure-deserialization-py",
    title: "Insecure deserialization (pickle)",
    description: "`pickle.load`/`loads` deserializes arbitrary objects and can execute code if the input is attacker-controlled (CWE-502).",
    severity: "critical",
    cwe: ["CWE-502"],
    owasp: "A08:2021 - Software and Data Integrity Failures",
    category: "sast",
    languages: PY,
    pattern: /pickle\.(load|loads)\(/,
    remediation: "Use a safe serialization format (JSON) for untrusted data, or cryptographically sign pickled payloads and verify before loading.",
  },
  {
    id: "sg-insecure-deserialization-java",
    title: "Insecure deserialization (ObjectInputStream)",
    description: "Native Java deserialization of untrusted data can lead to remote code execution via gadget chains (CWE-502).",
    severity: "critical",
    cwe: ["CWE-502"],
    owasp: "A08:2021 - Software and Data Integrity Failures",
    category: "sast",
    languages: JAVA,
    pattern: /new\s+ObjectInputStream\(/,
    remediation: "Avoid native Java deserialization of untrusted data; use a data format like JSON/Protobuf, or validate against an allow-list of classes.",
  },
  {
    id: "sg-yaml-unsafe-load",
    title: "Unsafe YAML deserialization",
    description: "`yaml.load` without `Loader=SafeLoader` can instantiate arbitrary Python objects from YAML content (CWE-502).",
    severity: "high",
    cwe: ["CWE-502"],
    owasp: "A08:2021 - Software and Data Integrity Failures",
    category: "sast",
    languages: PY,
    pattern: /yaml\.load\((?!.*Loader\s*=\s*(yaml\.)?SafeLoader)/,
    remediation: "Use `yaml.safe_load()` or pass `Loader=yaml.SafeLoader` explicitly.",
  },

  // ---------------- PATH TRAVERSAL ----------------
  {
    id: "sg-path-traversal",
    title: "Path Traversal",
    description:
      "A filesystem path is built by concatenating user input without normalization/allow-listing, which can let an attacker read or write files outside the intended directory using `../` sequences (CWE-22).",
    severity: "high",
    cwe: ["CWE-22"],
    owasp: "A01:2021 - Broken Access Control",
    category: "sast",
    languages: [...JS_TS, ...PY, ...JAVA, ...PHP],
    pattern:
      /(fs\.(readFile|writeFile|createReadStream|unlink)|open\(|File\()\s*\(\s*.*(req\.(params|query|body)|request\.(GET|POST)|\+\s*filename)/,
    remediation: "Resolve the path with `path.resolve`/`os.path.abspath`, then verify it stays within an allow-listed base directory before using it.",
  },

  // ---------------- SSRF ----------------
  {
    id: "sg-ssrf",
    title: "Potential Server-Side Request Forgery (SSRF)",
    description:
      "An outbound HTTP request is made to a URL built from user-controlled input, which could let an attacker make the server reach internal-only services (CWE-918).",
    severity: "high",
    cwe: ["CWE-918"],
    owasp: "A10:2021 - Server-Side Request Forgery",
    category: "sast",
    languages: [...JS_TS, ...PY, ...JAVA, ...GO],
    pattern:
      /(axios\.get\(|fetch\(|requests\.(get|post)\(|urlopen\(|http\.Get\()\s*\(?\s*(req\.(body|query|params)|request\.(GET|POST))/,
    remediation: "Validate destination URLs against an allow-list of hosts/schemes, and block requests to private/link-local IP ranges before making the call.",
  },

  // ---------------- AUTH / CONFIG ----------------
  {
    id: "sg-cors-wildcard",
    title: "Overly permissive CORS configuration",
    description: "`Access-Control-Allow-Origin` is set to `*` (optionally with credentials), allowing any origin to read responses (CWE-942).",
    severity: "medium",
    cwe: ["CWE-942"],
    owasp: "A05:2021 - Security Misconfiguration",
    category: "sast",
    languages: ANY,
    pattern: /Access-Control-Allow-Origin['"]?\s*[:,]\s*['"]\*['"]/,
    remediation: "Return an explicit allow-list of trusted origins instead of `*`, especially when `Access-Control-Allow-Credentials: true` is also set.",
  },
  {
    id: "sg-debug-mode-enabled",
    title: "Debug mode enabled",
    description: "Framework debug mode is on, which can leak stack traces, source code, and environment variables to end users (CWE-489).",
    severity: "medium",
    cwe: ["CWE-489"],
    owasp: "A05:2021 - Security Misconfiguration",
    category: "sast",
    languages: [...PY, ...JS_TS, ...PHP],
    pattern: /\b(DEBUG\s*=\s*True|app\.debug\s*=\s*true|debug:\s*true)\b/i,
    remediation: "Disable debug mode in any environment that isn't local development; drive it from an environment variable defaulting to `false`.",
  },
  {
    id: "sg-insecure-http",
    title: "Insecure HTTP URL (non-TLS)",
    description: "A hardcoded `http://` URL is used for what appears to be an API/service endpoint, exposing traffic to interception (CWE-319).",
    severity: "low",
    cwe: ["CWE-319"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    languages: ANY,
    pattern: /["'`]http:\/\/(?!localhost|127\.0\.0\.1|0\.0\.0\.0)[a-zA-Z0-9.\-]+/,
    remediation: "Use `https://` for any endpoint carrying real traffic; reserve `http://` for local development only.",
  },
  {
    id: "sg-jwt-none-alg",
    title: "JWT verification accepts 'none' algorithm",
    description: "JWT handling code allows the 'none' algorithm or disables signature verification, letting an attacker forge tokens (CWE-347).",
    severity: "critical",
    cwe: ["CWE-347"],
    owasp: "A02:2021 - Cryptographic Failures",
    category: "sast",
    languages: [...JS_TS, ...PY, ...JAVA],
    pattern: /algorithms?\s*[:=]\s*\[?['"]none['"]|verify\s*=\s*False.*jwt|jwt\.decode\([^)]*verify_signature['"]?\s*:\s*False/i,
    remediation: "Explicitly restrict accepted algorithms to a known safe set (e.g. `['RS256']`) and never disable signature verification.",
  },
  {
    id: "sg-missing-auth-admin",
    title: "Sensitive route without visible auth check",
    description:
      "A route/handler with an admin- or internal-sounding name doesn't show an auth/permission check nearby, which may indicate a broken access control gap (CWE-862).",
    severity: "medium",
    cwe: ["CWE-862"],
    owasp: "A01:2021 - Broken Access Control",
    category: "sast",
    languages: JS_TS,
    pattern: /(app|router)\.(get|post|put|delete)\(\s*["'`]\/(admin|internal|debug)[^,]*,\s*(async\s*)?\(?\s*(req|request)/i,
    remediation: "Add explicit authentication/authorization middleware in front of admin and internal routes, and verify it in tests.",
  },

  // ---------------- TEMPLATE / TAINT MARKERS ----------------
  {
    id: "sg-open-redirect",
    title: "Open Redirect",
    description: "A redirect target is taken directly from user input without validating it against an allow-list, enabling phishing redirects (CWE-601).",
    severity: "low",
    cwe: ["CWE-601"],
    owasp: "A01:2021 - Broken Access Control",
    category: "sast",
    languages: [...JS_TS, ...PY, ...PHP],
    pattern: /(res\.redirect\(|redirect\()\s*\(?\s*(req\.(query|params|body)|request\.GET)/,
    remediation: "Validate the redirect target against an allow-list of relative paths / known hosts before redirecting.",
  },
  {
    id: "sg-regex-dos",
    title: "Potential ReDoS (catastrophic backtracking)",
    description: "A regular expression contains nested quantifiers (e.g. `(a+)+`) that can cause catastrophic backtracking on crafted input, hanging the process (CWE-1333).",
    severity: "medium",
    cwe: ["CWE-1333"],
    owasp: "A06:2021 - Vulnerable and Outdated Components",
    category: "sast",
    languages: ANY,
    pattern: /\(([^()]*[+*]){1,}[^()]*\)[+*]/,
    remediation: "Rewrite the pattern to avoid nested/overlapping quantifiers, or validate input length before matching, or use a linear-time regex engine.",
  },
];

/** Return the file extension (lowercase, no dot) for a given file path. */
export function extOf(filePath: string): string {
  const m = /\.([a-zA-Z0-9]+)$/.exec(filePath);
  return m ? m[1].toLowerCase() : "";
}

export function rulesForLanguage(ext: string): Rule[] {
  return RULES.filter((r) => r.languages.includes("*") || r.languages.includes(ext));
}
