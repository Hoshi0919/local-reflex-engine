import json
from pathlib import Path
from typing import Dict, Any, Tuple
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, accuracy_score, f1_score
from skl2onnx import to_onnx

from .features import CommandFeatureExtractor

def train_and_export(
    train_path: Path,
    test_path: Path,
    onnx_output_path: Path,
    random_state: int = 42
) -> Dict[str, Any]:
    fe = CommandFeatureExtractor()
    
    with open(train_path, "r", encoding="utf-8") as f:
        train_data = [json.loads(line) for line in f]
    with open(test_path, "r", encoding="utf-8") as f:
        test_data = [json.loads(line) for line in f]
        
    X_train = np.array([fe.extract_dense_features(d["command"]) for d in train_data], dtype=np.float32)
    y_train = np.array([d["label"] for d in train_data], dtype=np.int64)
    
    X_test = np.array([fe.extract_dense_features(d["command"]) for d in test_data], dtype=np.float32)
    y_test = np.array([d["label"] for d in test_data], dtype=np.int64)
    
    clf = RandomForestClassifier(
        n_estimators=40,
        max_depth=8,
        min_samples_leaf=1,
        random_state=random_state
    )
    clf.fit(X_train, y_train)
    
    y_pred = clf.predict(X_test)
    acc = float(accuracy_score(y_test, y_pred))
    macro_f1 = float(f1_score(y_test, y_pred, average="macro"))
    rep = classification_report(y_test, y_pred, target_names=["SAFE", "SUSPICIOUS", "DANGEROUS"], output_dict=True)
    
    # Export ONNX model
    onnx_model = to_onnx(clf, X_train[:1])
    onnx_output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(onnx_output_path, "wb") as f:
        f.write(onnx_model.SerializeToString())
        
    metrics = {
        "accuracy": round(acc, 4),
        "macro_f1": round(macro_f1, 4),
        "train_samples": len(train_data),
        "test_samples": len(test_data),
        "feature_count": X_train.shape[1],
        "detailed_report": rep,
        "onnx_model_path": str(onnx_output_path)
    }
    
    metrics_path = onnx_output_path.with_name("metrics.json")
    with open(metrics_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2)
        
    return metrics

if __name__ == "__main__":
    base = Path(__file__).resolve().parent.parent.parent
    tr = base / "data" / "train.jsonl"
    te = base / "data" / "test.jsonl"
    out = base / "models" / "reflex_rf.onnx"
    m = train_and_export(tr, te, out)
    print("Training and export complete!")
    print(f"Accuracy: {m['accuracy']}, Macro F1: {m['macro_f1']}")
