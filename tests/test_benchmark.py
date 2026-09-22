import unittest
import time
from reflex_engine import ReflexEngine, Tier

class TestBenchmark(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.engine = ReflexEngine()

    def test_tier_0_latency_performance(self):
        cmd = "git status"
        # Warmup
        for _ in range(50):
            self.engine.judge(cmd)

        n = 1000
        t0 = time.perf_counter()
        for _ in range(n):
            v = self.engine.judge(cmd)
        elapsed_total = time.perf_counter() - t0
        avg_us = (elapsed_total / n) * 1e6

        print(f"\n[BENCHMARK] Tier-0 Rules avg latency: {avg_us:.2f} µs ({avg_us/1000:.4f} ms)")
        self.assertLess(avg_us, 100.0, f"Tier-0 latency {avg_us}µs exceeded 100µs budget")

    def test_tier_1_latency_performance(self):
        cmd = "pytest tests/test_benchmark.py --verbose -s"
        # Warmup
        for _ in range(50):
            self.engine.judge(cmd)

        n = 500
        t0 = time.perf_counter()
        for _ in range(n):
            v = self.engine.judge(cmd)
        elapsed_total = time.perf_counter() - t0
        avg_us = (elapsed_total / n) * 1e6

        print(f"\n[BENCHMARK] Tier-1 Feature+ONNX avg latency: {avg_us:.2f} µs ({avg_us/1000:.4f} ms)")
        # 10ms is 10,000µs; we assert under 2,000µs (2ms)
        self.assertLess(avg_us, 2000.0, f"Tier-1 latency {avg_us}µs exceeded 2000µs budget")

if __name__ == "__main__":
    unittest.main()
