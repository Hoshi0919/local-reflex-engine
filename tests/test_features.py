import unittest
import numpy as np
from reflex_engine.features import CommandFeatureExtractor, shannon_entropy

class TestFeatures(unittest.TestCase):
    def setUp(self):
        self.fe = CommandFeatureExtractor()

    def test_feature_dimension(self):
        vec = self.fe.extract_dense_features("git status")
        self.assertIsInstance(vec, np.ndarray)
        self.assertEqual(len(vec), len(self.fe.feature_names))
        self.assertEqual(len(vec), 17)

    def test_shannon_entropy(self):
        self.assertEqual(shannon_entropy(""), 0.0)
        e1 = shannon_entropy("aaaaaa")
        self.assertEqual(e1, 0.0)
        e2 = shannon_entropy("abcdef")
        self.assertGreater(e2, 2.0)

    def test_batch_extraction(self):
        cmds = ["git status", "ls -la", "echo hello"]
        batch = self.fe.extract_batch(cmds)
        self.assertEqual(batch.shape, (3, 17))

    def test_indicators_hit(self):
        # Sensitive path hit
        vec_sensitive = self.fe.extract_dense_features("cat /etc/hosts")
        self.assertGreaterEqual(vec_sensitive[8], 1.0) # sensitive_path_hits

        # Dangerous flag hit
        vec_flag = self.fe.extract_dense_features("rm -rf dist")
        self.assertGreaterEqual(vec_flag[11], 1.0) # dangerous_flag_hits

if __name__ == "__main__":
    unittest.main()
