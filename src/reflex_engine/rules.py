import re
from typing import Optional, Tuple
from .schema import SafetyLevel

# Pre-compiled high-severity patterns for microsecond matching
LETHAL_PATTERNS = [
    (re.compile(r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(--no-preserve-root\s+)?(/\*?|~/\*?|\.\./\*?)(\s|$)', re.IGNORECASE),
     "Recursive forced deletion of root, home, or parent directory"),
    (re.compile(r'\bmkfs(\.[a-z0-9]+)?\s+/dev/[a-z0-9]+', re.IGNORECASE),
     "Filesystem creation on raw block device"),
    (re.compile(r'\bdd\s+.*of=/dev/(sd[a-z]|nvme[0-9]|vd[a-z]|hd[a-z]|mmcblk[0-9])', re.IGNORECASE),
     "Direct raw block device overwriting via dd"),
    (re.compile(r':\(\)\s*\{[^}]*:\s*\|\s*:[^}]*&\s*\};:', re.IGNORECASE),
     "Classic bash fork bomb"),
    (re.compile(r'/dev/tcp/(\d{1,3}\.){3}\d{1,3}/\d+', re.IGNORECASE),
     "Direct bash TCP socket reverse shell"),
    (re.compile(r'\bnc(\.traditional)?\s+(-[a-zA-Z]*e\s+|--exec\s+)/bin/(sh|bash)', re.IGNORECASE),
     "Netcat reverse shell with shell execution flag"),
    (re.compile(r'/proc/sysrq-trigger', re.IGNORECASE),
     "Hardware kernel trigger panic manipulation"),
    (re.compile(r'\b(curl|wget)\s+[^|;]+(\|\s*(sh|bash|zsh|python[0-9]?|perl))\b', re.IGNORECASE),
     "Piping untrusted remote network script directly into shell execution"),
    (re.compile(r'base64\s+(-d|--decode)\s*\|\s*(sh|bash|zsh|python[0-9]?)', re.IGNORECASE),
     "Obfuscated base64 decoded shell execution"),
    (re.compile(r'\bcat\s+.*id_(rsa|ed25519|ecdsa).*\|\s*(curl|nc|socat|wget)', re.IGNORECASE),
     "Private SSH key exfiltration via network pipe"),
]

SUSPICIOUS_PATTERNS = [
    (re.compile(r'\bgit\s+push\s+.*(--force|-f)\b', re.IGNORECASE),
     "Destructive remote git history overwrite via force push"),
    (re.compile(r'\bgit\s+reset\s+--hard\b', re.IGNORECASE),
     "Discarding uncommitted working tree modifications via git hard reset"),
    (re.compile(r'\bgit\s+clean\s+-[a-zA-Z]*f', re.IGNORECASE),
     "Untracked file wiping via git clean"),
    (re.compile(r'\bchmod\s+(-[a-zA-Z]*R\s+)?(0?777|a\+rwx)\b', re.IGNORECASE),
     "Overly permissive chmod 777 permissions"),
    (re.compile(r'\bkill\s+-9\s+\$?\w+|\bpkill\s+-9\b', re.IGNORECASE),
     "Unconditional SIGKILL process termination"),
    (re.compile(r'\b(systemctl|service)\s+(stop|restart|disable)\b', re.IGNORECASE),
     "System service disruption"),
    (re.compile(r'\b(iptables|ufw)\s+.*(flush|disable|reset)\b', re.IGNORECASE),
     "Firewall rule flush or disabling"),
    (re.compile(r'\brm\s+(-[a-zA-Z]*r[a-zA-Z]*f|-[a-zA-Z]*f[a-zA-Z]*r)\s+(node_modules|dist|build|\.venv|\.cache)\b', re.IGNORECASE),
     "Forced recursive directory cleanup of project build artifact"),
    (re.compile(r'\bchown\s+-R\s+', re.IGNORECASE),
     "Recursive filesystem ownership change"),
]

# Fast safe whitelist pattern (pure inspection / read / build)
SAFE_PATTERNS = [
    re.compile(r'^\s*(pwd|whoami|date|uptime|id)(\s+.*)?$'),
    re.compile(r'^\s*uname(\s+-[a-zA-Z]+)?\s*$'),
    re.compile(r'^\s*git\s+(status|log|diff|branch|tag|show|rev-parse|remote|describe)(\s+[^;&|]+)?$'),
    re.compile(r'^\s*(ls|dir)(\s+-[a-zA-Z0-9]+)*(\s+[a-zA-Z0-9_./-]+)*\s*$'),
    re.compile(r'^\s*(cat|head|tail|grep|rg|find|wc|file|stat|jq|which|whereis|env)(\s+[^;&|]+)*$'),
    re.compile(r'^\s*(pytest|python3?\s+-m\s+unittest|cargo\s+(build|check|test)|go\s+test|npm\s+test)(\s+[^;&|]+)*$'),
    re.compile(r'^\s*echo\s+["\']?[a-zA-Z0-9_., !?-]+["\']?\s*$'),
]

class RuleEngine:
    @staticmethod
    def match(command: str) -> Optional[Tuple[SafetyLevel, float, str]]:
        """
        Microsecond-level deterministic pattern scanner.
        Returns (level, score, reason) or None if inconclusive.
        """
        cmd = command.strip()
        if not cmd:
            return SafetyLevel.SAFE, 0.0, "Empty command"

        # Check dangerous lethal patterns first
        for pattern, reason in LETHAL_PATTERNS:
            if pattern.search(cmd):
                return SafetyLevel.DANGEROUS, 1.0, reason

        # Check suspicious patterns
        for pattern, reason in SUSPICIOUS_PATTERNS:
            if pattern.search(cmd):
                return SafetyLevel.SUSPICIOUS, 0.75, reason

        # Check safe whitelist patterns (only if no piping or command chaining)
        if not any(token in cmd for token in [";", "&&", "||", "|", "`", "$("]):
            for pattern in SAFE_PATTERNS:
                if pattern.match(cmd):
                    return SafetyLevel.SAFE, 0.0, "Matched deterministic safe read-only signature"

        return None
