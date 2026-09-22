import unittest
from pathlib import Path
from reflex_engine import ReflexEngine, SafetyLevel, Tier

class TestReflexEngine(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ReflexEngine()

    def test_tier_0_rule_routing(self):
        v = self.engine.judge("git status")
        self.assertEqual(v.level, SafetyLevel.SAFE)
        self.assertEqual(v.tier, Tier.TIER_0_RULES)
        self.assertLess(v.latency_us, 500) # strictly under 500 us

    def test_tier_1_onnx_routing(self):
        # A normal tool command that does not match strict static rules
        v = self.engine.judge("uv run python -m build")
        self.assertIn(v.tier, [Tier.TIER_1_ONNX, Tier.TIER_FALLBACK])
        self.assertLess(v.latency_us, 10000) # strictly under 10ms
        self.assertIn("score", v.to_dict())

    def test_judge_batch(self):
        cmds = ["pwd", "git status", "npm install express"]
        verdicts = self.engine.judge_batch(cmds)
        self.assertEqual(len(verdicts), 3)
        self.assertEqual(verdicts[0].command, "pwd")
        self.assertEqual(verdicts[0].level, SafetyLevel.SAFE)

    def test_custom_thresholds_fallback(self):
        # Extremely strict margin threshold triggers fallback
        strict_engine = ReflexEngine(margin_threshold=0.99)
        v = strict_engine.judge("npm install express")
        # Since margin won't be >= 0.99, it should trigger TIER_FALLBACK
        self.assertEqual(v.tier, Tier.TIER_FALLBACK)

if __name__ == "__main__":
    unittest.main()
