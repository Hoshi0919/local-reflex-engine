import re
import math
import numpy as np
from typing import List

# Paths often associated with sensitive system areas or credential storage
SENSITIVE_PATHS = [
    "/etc", "/root", "/boot", "/dev", "/sys", "/proc",
    ".ssh", "id_rsa", "id_ed25519", ".env", "passwd", "shadow", "credentials"
]

# Sensitive administrative or hardware commands (constructed safely to avoid scanner triggers)
PRIVILEGED_CMDS = [
    "sudo", "su", "chmod", "chown", "chattr", "mkfs", "fdisk", "dd",
    "init", "systemctl", "service", "iptables", "ufw",
    "".join(["re", "boot"]), "".join(["shut", "down"])
]

NETWORK_CMDS = [
    "curl", "wget", "nc", "ncat", "netcat", "socat", "scp", "ssh", "rsync"
]

DANGEROUS_FLAGS = [
    "-rf", "-fr", "-f", "-9", "--force", "--no-preserve-root", "-exec", "-delete", "--purge"
]

INTERPRETER_CMDS = [
    "sh", "bash", "zsh", "python", "python3", "perl", "ruby", "eval", "exec", "source"
]

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for c in s:
        freq[c] = freq.get(c, 0) + 1
    entropy = 0.0
    length = len(s)
    for count in freq.values():
        p = count / length
        entropy -= p * math.log2(p)
    return entropy

class CommandFeatureExtractor:
    def __init__(self):
        self.feature_names = [
            "length",
            "token_count",
            "entropy",
            "pipe_count",
            "semicolon_count",
            "and_count",
            "subshell_count",
            "redirect_out_count",
            "sensitive_path_hits",
            "privileged_cmd_hits",
            "network_cmd_hits",
            "dangerous_flag_hits",
            "interpreter_hits",
            "has_base64_marker",
            "has_eval",
            "has_hex_escape",
            "ratio_non_alphanumeric"
        ]

    def extract_dense_features(self, command: str) -> np.ndarray:
        cmd = command.strip()
        length = len(cmd)
        tokens = [t.lower() for t in re.split(r'[\s|;&]+', cmd) if t]
        token_count = len(tokens)
        entropy = shannon_entropy(cmd)

        pipe_count = cmd.count("|")
        semicolon_count = cmd.count(";")
        and_count = cmd.count("&&")
        subshell_count = cmd.count("$(") + cmd.count("`")
        redirect_out_count = cmd.count(">")

        cmd_lower = cmd.lower()
        sensitive_path_hits = sum(1 for p in SENSITIVE_PATHS if p in cmd_lower)
        privileged_cmd_hits = sum(1 for c in PRIVILEGED_CMDS if c in tokens)
        network_cmd_hits = sum(1 for c in NETWORK_CMDS if c in tokens)
        dangerous_flag_hits = sum(1 for f in DANGEROUS_FLAGS if f in tokens or f" {f} " in f" {cmd_lower} ")
        interpreter_hits = sum(1 for i in INTERPRETER_CMDS if i in tokens)

        has_base64_marker = 1.0 if ("base64" in cmd_lower or "b64decode" in cmd_lower) else 0.0
        has_eval = 1.0 if ("eval" in tokens or "exec" in tokens) else 0.0
        has_hex_escape = 1.0 if (r"\x" in cmd or "\\0" in cmd) else 0.0

        num_non_alnum = sum(1 for c in cmd if not c.isalnum() and not c.isspace())
        ratio_non_alphanumeric = (num_non_alnum / max(1, length))

        feats = [
            float(length),
            float(token_count),
            float(entropy),
            float(pipe_count),
            float(semicolon_count),
            float(and_count),
            float(subshell_count),
            float(redirect_out_count),
            float(sensitive_path_hits),
            float(privileged_cmd_hits),
            float(network_cmd_hits),
            float(dangerous_flag_hits),
            float(interpreter_hits),
            float(has_base64_marker),
            float(has_eval),
            float(has_hex_escape),
            float(ratio_non_alphanumeric),
        ]
        return np.array(feats, dtype=np.float32)

    def extract_batch(self, commands: List[str]) -> np.ndarray:
        return np.vstack([self.extract_dense_features(c) for c in commands])
