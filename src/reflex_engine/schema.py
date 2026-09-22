from dataclasses import dataclass, field
from enum import Enum
from typing import List

class SafetyLevel(str, Enum):
    SAFE = "SAFE"
    SUSPICIOUS = "SUSPICIOUS"
    DANGEROUS = "DANGEROUS"

class Tier(str, Enum):
    TIER_0_RULES = "TIER_0_RULES"
    TIER_1_ONNX = "TIER_1_ONNX"
    TIER_FALLBACK = "TIER_FALLBACK"

@dataclass
class Verdict:
    level: SafetyLevel
    score: float
    reasons: List[str] = field(default_factory=list)
    tier: Tier = Tier.TIER_0_RULES
    latency_us: float = 0.0
    command: str = ""

    @property
    def latency_ms(self) -> float:
        return self.latency_us / 1000.0

    def to_dict(self):
        return {
            "command": self.command,
            "level": self.level.value,
            "score": round(self.score, 4),
            "reasons": self.reasons,
            "tier": self.tier.value,
            "latency_us": round(self.latency_us, 1),
            "latency_ms": round(self.latency_ms, 3),
        }
