import time
from pathlib import Path
from typing import List, Optional, Union
import numpy as np
import onnxruntime as ort

from .schema import SafetyLevel, Tier, Verdict
from .rules import RuleEngine
from .features import CommandFeatureExtractor

LABEL_TO_SAFETY = {
    0: SafetyLevel.SAFE,
    1: SafetyLevel.SUSPICIOUS,
    2: SafetyLevel.DANGEROUS
}

class ReflexEngine:
    def __init__(
        self,
        onnx_model_path: Optional[Union[str, Path]] = None,
        confidence_threshold: float = 0.50,
        margin_threshold: float = 0.15
    ):
        if onnx_model_path is None:
            default_path = Path(__file__).resolve().parent.parent.parent / "models" / "reflex_rf.onnx"
            self.model_path = default_path
        else:
            self.model_path = Path(onnx_model_path)
            
        if not self.model_path.exists():
            raise FileNotFoundError(f"ONNX model not found at {self.model_path}")

        # Configure fast CPU inference
        opts = ort.SessionOptions()
        opts.intra_op_num_threads = 1
        opts.inter_op_num_threads = 1
        opts.graph_optimization_level = ort.GraphOptimizationLevel.ORT_ENABLE_ALL
        
        self.session = ort.InferenceSession(str(self.model_path), sess_options=opts)
        self.input_name = self.session.get_inputs()[0].name
        self.output_names = [o.name for o in self.session.get_outputs()]
        
        self.feature_extractor = CommandFeatureExtractor()
        self.confidence_threshold = confidence_threshold
        self.margin_threshold = margin_threshold

    def judge(self, command: str) -> Verdict:
        t0 = time.perf_counter()
        cmd = command.strip()

        # --- Tier 0: Deterministic Rule Engine (<10 us) ---
        rule_result = RuleEngine.match(cmd)
        if rule_result is not None:
            level, score, reason = rule_result
            latency_us = (time.perf_counter() - t0) * 1e6
            return Verdict(
                level=level,
                score=score,
                reasons=[f"[Tier-0 Rule] {reason}"],
                tier=Tier.TIER_0_RULES,
                latency_us=latency_us,
                command=cmd
            )

        # --- Tier 1: Feature Extraction + ONNX Inference (<100 us) ---
        feats = self.feature_extractor.extract_dense_features(cmd)
        inputs = {self.input_name: feats.reshape(1, -1)}
        raw_outputs = self.session.run(self.output_names, inputs)
        
        # skl2onnx outputs: [label_array, probabilities_map_list]
        pred_label = int(raw_outputs[0][0])
        prob_dict = raw_outputs[1][0] if len(raw_outputs) > 1 else {}
        
        if prob_dict:
            scores = sorted(prob_dict.values(), reverse=True)
            top_prob = scores[0]
            second_prob = scores[1] if len(scores) > 1 else 0.0
            margin = top_prob - second_prob
        else:
            top_prob = 1.0
            margin = 1.0

        # Assess if fallback to higher tier (LLM / user confirmation) is needed
        is_ambiguous = (top_prob < self.confidence_threshold) or (margin < self.margin_threshold)
        
        if is_ambiguous:
            tier = Tier.TIER_FALLBACK
            reason = f"[Tier-1 Low Margin] Confidence {top_prob:.2f} (margin {margin:.2f}), flagged for fallback/review"
        else:
            tier = Tier.TIER_1_ONNX
            reason = f"[Tier-1 ONNX] Classified as {LABEL_TO_SAFETY[pred_label].value} (conf={top_prob:.2f})"

        level = LABEL_TO_SAFETY.get(pred_label, SafetyLevel.SUSPICIOUS)
        latency_us = (time.perf_counter() - t0) * 1e6

        return Verdict(
            level=level,
            score=float(top_prob),
            reasons=[reason],
            tier=tier,
            latency_us=latency_us,
            command=cmd
        )

    def judge_batch(self, commands: List[str]) -> List[Verdict]:
        return [self.judge(c) for c in commands]
