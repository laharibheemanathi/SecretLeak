"""Detection rule definitions.

Each rule documents why it has its chosen severity. Important honesty notes:

* A pattern match does NOT prove a credential is valid, active or exploitable.
* Provider-specific rules (GitHub, AWS, ...) match real format shapes and are
  rated HIGH; generic heuristics (assignments, entropy) are MEDIUM/LOW.
* Placeholder values (YOUR_API_KEY, CHANGEME, REDACTED, ${VAR}, ...) are
  filtered centrally so rules never need to re-implement that logic.
"""

from __future__ import annotations

from dataclasses import dataclass, field

SEVERITY_CRITICAL = "critical"
SEVERITY_HIGH = "high"
SEVERITY_MEDIUM = "medium"
SEVERITY_LOW = "low"

SEVERITY_ORDER = {
    SEVERITY_CRITICAL: 4,
    SEVERITY_HIGH: 3,
    SEVERITY_MEDIUM: 2,
    SEVERITY_LOW: 1,
}

CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"


@dataclass(frozen=True)
class Rule:
    id: str
    name: str
    category: str
    severity: str
    confidence: str
    pattern: str
    description: str
    why_severity: str
    remediation: str
    # Gate generic rules behind an entropy check to cut false positives.
    entropy_gate: float | None = None
    # Rule spans multiple lines (private key blocks).
    multiline: bool = False
    # Higher number wins when matches overlap (private keys beat everything).
    priority: int = 100
    # Capture group index that contains the secret value (defaults to full match).
    value_group: int = 0
    tags: tuple[str, ...] = field(default_factory=tuple)


PROVIDER_REMEDIATION = (
    "Revoke the exposed credential immediately in the provider's console, "
    "issue a replacement, and update every system that used it. "
    "Review recent account/activity logs for unauthorized use."
)


RULES: tuple[Rule, ...] = (
    # ------------------------------------------------------------------ CRITICAL
    Rule(
        id="private-key-block",
        name="Private key block (PEM)",
        category="Private key",
        severity=SEVERITY_CRITICAL,
        confidence=CONFIDENCE_HIGH,
        pattern=r"-----BEGIN (?:RSA |EC |DSA |DSA |OPENSSH |ENCRYPTED |PGP |)PRIVATE KEY-----",
        multiline=True,
        priority=1000,
        description=(
            "Matches PEM/PGP private key header lines (e.g. RSA, EC, OPENSSH). "
            "The key body is never retained by SecretLeak; only the header and the "
            "number of redacted lines are recorded."
        ),
        why_severity=(
            "CRITICAL because an exposed private key directly grants cryptographic "
            "identity (SSH access, TLS certificates, code signing) with no revocation "
            "step as simple as rotating a token."
        ),
        remediation=(
            "Assume the key is compromised. Generate a new key pair, install the new "
            "public key, remove the old one from authorized_keys / certificate authorities, "
            "then purge the key from Git history (coordinate a rewrite, notify "
            "collaborators) and rotate anything the key protected. "
            "Never rewrite history automatically — SecretLeak does not do that for you."
        ),
    ),
    # ---------------------------------------------------------------------- HIGH
    Rule(
        id="github-pat",
        name="GitHub personal access token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bghp_[A-Za-z0-9]{36}\b",
        priority=985,
        description="Matches GitHub classic personal access tokens (ghp_ + 36 base62 chars).",
        why_severity=(
            "HIGH: provider-specific format with a well-known prefix, so precision is high; "
            "a valid token can grant repository and org access. Validity is not verified."
        ),
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="github-fine-grained-pat",
        name="GitHub fine-grained personal access token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bgithub_pat_[A-Za-z0-9]{22}_[A-Za-z0-9]{59}\b",
        priority=980,
        description="Matches GitHub fine-grained PATs (github_pat_ + 22 chars + _ + 59 chars).",
        why_severity="HIGH: provider-specific format; grants scoped repository access if valid.",
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="github-oauth-app-token",
        name="GitHub OAuth/App token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\b(?:gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b",
        priority=975,
        description="Matches GitHub OAuth user-to-server (gho_), user-to-server (ghu), server-to-server (ghs) and refresh (ghr) tokens.",
        why_severity="HIGH: provider-specific token formats that can act with a user's or app's permissions.",
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="gitlab-pat",
        name="GitLab personal access token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bglpat-[A-Za-z0-9_-]{20,200}\b",
        priority=970,
        description="Matches GitLab personal access tokens (glpat- prefix).",
        why_severity="HIGH: provider-specific prefix; grants API/repository access if valid.",
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="gitlab-runner-token",
        name="GitLab runner registration token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bglrt-[A-Za-z0-9_-]{20,200}\b",
        priority=965,
        description="Matches GitLab runner registration tokens (glrt- prefix).",
        why_severity="HIGH: a runner token can attach a malicious CI runner to a project.",
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="slack-token",
        name="Slack API token",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bxox[baprse]-[A-Za-z0-9-]{10,200}\b",
        priority=960,
        description="Matches Slack tokens (xoxb-, xoxp-, xoxa-, xoxs-, xoxe-).",
        why_severity="HIGH: provider-specific prefixes; bot/user tokens can read and post messages.",
        remediation=PROVIDER_REMEDIATION,
    ),
    Rule(
        id="slack-webhook-url",
        name="Slack incoming webhook URL",
        category="Provider token",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=r"\bhttps://hooks\.slack\.com/services/T[A-Za-z0-9_]{6,}/B[A-Za-z0-9_]{6,}/[A-Za-z0-9_]{16,}\b",
        priority=955,
        description="Matches Slack incoming-webhook URLs, which embed an access token in the path.",
        why_severity="HIGH: anyone with the URL can post to the channel; webhooks cannot be rotated except by recreating.",
        remediation=PROVIDER_REMEDIATION + " For webhooks, delete the webhook and create a new one.",
    ),
    Rule(
        id="aws-access-key-id",
        name="AWS access key ID",
        category="Cloud credential",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_MEDIUM,
        pattern=r"\b(?:AKIA|ASIA|AIDA|AROA|ABIA|ACCA|AGPA|AIPA|ANPA|ANVA|APKA)[A-Z0-9]{16}\b",
        priority=940,
        description=(
            "Matches AWS access key ID prefixes (AKIA static keys, ASIA temporary STS keys, "
            "and other IAM identifier prefixes) followed by 16 uppercase alphanumeric chars."
        ),
        why_severity=(
            "HIGH: an access key ID alone identifies an IAM credential; combined with a secret "
            "access key it grants API access. The ID by itself is not sufficient to authenticate."
        ),
        remediation=(
            "Deactivate and delete the access key in the AWS IAM console, create a replacement, "
            "and check CloudTrail for activity performed with the exposed key ID. "
            "A secret access key is never derivable from the key ID."
        ),
    ),
    Rule(
        id="database-connection-string",
        name="Database connection string with embedded credentials",
        category="Database credential",
        severity=SEVERITY_HIGH,
        confidence=CONFIDENCE_HIGH,
        pattern=(
            r"\b(?:postgresql|postgres|mysql|mariadb|mongodb\+srv|mongodb|redis|rediss|"
            r"amqps?|mssql|jdbc:(?:postgresql|mysql|oracle|sqlserver))://"
            r"[^\s'\"<>:@/]+:[^\s'\"<>@/]{4,}@[A-Za-z0-9.\-\[\]:0-9]{2,}"
        ),
        priority=900,
        description="Matches database URLs that embed a username and password (postgres://user:pass@host, mysql, mongo, redis, amqp, JDBC).",
        why_severity="HIGH: embedded database credentials usually grant direct data access with no second factor.",
        remediation=(
            "Rotate the database password, move the connection string to an environment variable "
            "or a secrets manager, and use short-lived credentials where possible."
        ),
    ),
    # -------------------------------------------------------------------- MEDIUM
    Rule(
        id="jwt-token",
        name="JWT-like token",
        category="Session token",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b",
        priority=750,
        description=(
            "Matches strings shaped like a JSON Web Token (base64url header starting with eyJ, "
            "payload, signature). Header and payload are only base64-encoded, not encrypted."
        ),
        why_severity=(
            "MEDIUM: a live JWT can impersonate a session until it expires, but tokens are "
            "time-limited and we cannot tell from the string whether it is valid."
        ),
        remediation=(
            "Invalidate the session server-side (revoke the token / bump the session), shorten "
            "token lifetimes, and stop logging full tokens. If it is a signing key misdetected "
            "as a JWT, treat it as a secret and rotate it anyway."
        ),
    ),
    Rule(
        id="authorization-bearer",
        name="Authorization header with bearer/basic credential",
        category="Authorization header",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=r"(?i)\bauthorization\b[^\n]{0,60}?[:=]\s*[\"']?(?:bearer|basic)\s+([A-Za-z0-9._\-+/=]{16,1024})",
        value_group=1,
        priority=700,
        description="Matches Authorization headers or assignments containing a Bearer/Basic credential.",
        why_severity="MEDIUM: likely a live credential for some API, but format is generic and context varies.",
        remediation=(
            "Rotate the credential, remove hardcoded headers from code and logs, and load them "
            "from environment variables or a secret manager at runtime."
        ),
    ),
    Rule(
        id="url-credentials",
        name="URL with embedded username/password",
        category="Credential in URL",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=r"\b[a-z][a-z0-9+.\-]{1,20}://[A-Za-z0-9._~%$-]{1,64}:[^\s'\"<>@/]{3,128}@[A-Za-z0-9.\-]",
        priority=600,
        description="Matches any URL that embeds user:password@ (git remotes, webhooks, internal services).",
        why_severity="MEDIUM: credentials in URLs leak through logs, shell history and referrers; format is generic.",
        remediation=(
            "Rotate the embedded password, switch to SSH keys or credential helpers for Git remotes, "
            "and keep credentials out of URLs entirely."
        ),
    ),
    Rule(
        id="api-key-assignment",
        name="API key / token assignment",
        category="Generic credential assignment",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=(
            r"(?i)\b(?:api[_-]?key|apikey|api[_-]?secret|secret[_-]?key|client[_-]?secret|"
            r"access[_-]?token|auth[_-]?token|refresh[_-]?token|private[_-]?token|"
            r"access[_-]?key[_-]?secret|secret[_-]?access[_-]?key)\b"
            r"\s*(?:=|:|=>)\s*[\"']?([A-Za-z0-9_\-/+.]{12,256})[\"']?"
        ),
        value_group=1,
        entropy_gate=3.2,
        priority=500,
        description=(
            "Matches assignment-style credential declarations (api_key = \"...\", "
            "\"clientSecret\": \"...\") after an entropy gate and placeholder filter."
        ),
        why_severity=(
            "MEDIUM: a hardcoded credential in source, but the format is generic so we cannot "
            "identify the provider; some matches will be configuration scaffolding."
        ),
        remediation=(
            "Move the value to an environment variable or secrets manager, rotate it (treat any "
            "committed credential as exposed), and add the pattern to your pre-commit checks."
        ),
    ),
    Rule(
        id="password-assignment",
        name="Password assignment",
        category="Generic credential assignment",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=r"(?i)\b(?:password|passwd|pwd)\b\s*(?:=|:|=>)\s*[\"']?([^\s\"';&,]{6,128})[\"']?",
        value_group=1,
        priority=450,
        description="Matches literal password assignments in code and configuration files.",
        why_severity="MEDIUM: literal passwords in source are exposed to everyone with repository access.",
        remediation=(
            "Rotate the password, load it from the environment or a secrets manager, and audit "
            "who had access to the repository meanwhile."
        ),
    ),
    Rule(
        id="env-var-credential",
        name="Credential assignment in environment-style file",
        category="Environment file",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=(
            r"(?m)^[ \t]*(?:export[ \t]+)?[A-Za-z0-9_]*"
            r"(?:PASSWORD|PASSWD|SECRET|TOKEN|API_?KEY|ACCESS_KEY|PRIVATE_KEY|CREDENTIALS?)"
            r"[A-Za-z0-9_]*[ \t]*=[ \t]*[\"']?([^\s\"'#]{6,128})"
        ),
        value_group=1,
        priority=400,
        description="Matches .env-style credential lines (MY_SECRET=..., export DB_PASSWORD=...).",
        why_severity="MEDIUM: .env files are frequently committed by accident and hold live service credentials.",
        remediation=(
            "Rotate the value, add the file to .gitignore, purge it from history if it was committed, "
            "and provide a safe .env.example with placeholders instead."
        ),
    ),
    Rule(
        id="log-credential-leak",
        name="Credential-like value in application log line",
        category="Log leak",
        severity=SEVERITY_MEDIUM,
        confidence=CONFIDENCE_MEDIUM,
        pattern=(
            r"(?i)(?:level=(?:info|debug|warn|warning|error)|\b(?:INFO|DEBUG|WARN|ERROR)\b|"
            r"\blogged in as\b|\brequest to\b).{0,200}?\b(?:token|api[_-]?key|secret|password|"
            r"credential)s?\b[\"']?\s*[=:]\s*[\"']?([A-Za-z0-9_\-./+=]{12,256})"
        ),        value_group=1,
        entropy_gate=3.2,
        priority=520,  # beats generic assignment rules inside log lines
        description=(
            "Matches structured log lines that echo a credential-like value"
            "(e.g. 'INFO token=...'). Logs are shipped everywhere, so a leak here spreads."
        ),
        why_severity="MEDIUM: log lines frequently end up in shared aggregators and support tickets.",
        remediation=(
            "Stop logging the value (log a redacted identifier instead), rotate the credential, "
            "and scrub affected log retention where feasible."
        ),
    ),
    # ---------------------------------------------------------------------- LOW
    # The generic high-entropy rule lives in the engine (heuristic, not regex)
    # and always reports severity LOW / confidence LOW.
)

RULES_BY_ID: dict[str, Rule] = {rule.id: rule for rule in RULES}

ENTROPY_RULE_ID = "generic-high-entropy"
ENTROPY_SEVERITY = SEVERITY_LOW
ENTROPY_CONFIDENCE = CONFIDENCE_LOW

ENTROPY_RULE_META = Rule(
    id=ENTROPY_RULE_ID,
    name="Generic high-entropy string",
    category="Heuristic",
    severity=ENTROPY_SEVERITY,
    confidence=ENTROPY_CONFIDENCE,
    pattern="",  # computed in the engine
    description=(
        "Flags long, mixed-character strings with high Shannon entropy that do not match any "
        "provider rule. These are candidates only — random-looking data is often a hash or a "
        "build artifact."
    ),
    why_severity=(
        "LOW: entropy alone proves nothing; the string may be a checksum, salt, or identifier. "
        "It is surfaced so a human can decide."
    ),
    remediation=(
        "Identify what the value is. If it is a credential, rotate it and move it to a secrets "
        "manager. If it is an artifact (hash, UUID, salt), dismiss this finding as a false positive."
    ),
)
