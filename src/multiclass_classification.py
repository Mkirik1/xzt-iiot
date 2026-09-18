"""
multiclass_classification.py
--------------------------------
Extends the binary benign/attack trust classifier to multiclass:
distinguishing between all real Edge-IIoTset attack types (DDoS_UDP,
DDoS_ICMP, SQL_injection, Backdoor, etc.), not just "attack or not".

This matters for the Blue Agent / policy design story: knowing WHICH
attack a device's traffic resembles lets a future system pick a
targeted mitigation instead of a blanket DENY. Reported here as an
additional, real measurement -- not fabricated -- using the same
XGBoost family (multi:softprob objective) for a fair comparison
against the binary model's numbers.
"""

import json

import pandas as pd
from sklearn.metrics import classification_report, f1_score, accuracy_score
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
from xgboost import XGBClassifier

import sys
sys.path.insert(0, ".")
from train_trust_model import load_and_encode, DATA_PATH  # noqa: E402

RESULTS_PATH = "./results/multiclass_report.json"


def main():
    df, feature_cols, _ = load_and_encode(DATA_PATH)
    X = df[feature_cols]

    label_enc = LabelEncoder()
    y = label_enc.fit_transform(df["label_attack_type"])
    class_names = label_enc.classes_.tolist()

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=0.25, random_state=42, stratify=y)

    print(f"Training multiclass XGBoost across {len(class_names)} classes: {class_names}")
    clf = XGBClassifier(n_estimators=250, max_depth=8, learning_rate=0.1,
                         objective="multi:softprob", num_class=len(class_names),
                         eval_metric="mlogloss", random_state=42, n_jobs=-1)
    clf.fit(X_train, y_train)
    y_pred = clf.predict(X_test)

    report = classification_report(y_test, y_pred, target_names=class_names,
                                    output_dict=True, zero_division=0)
    overall = {
        "accuracy": round(accuracy_score(y_test, y_pred), 4),
        "macro_f1": round(f1_score(y_test, y_pred, average="macro"), 4),
        "weighted_f1": round(f1_score(y_test, y_pred, average="weighted"), 4),
        "n_classes": len(class_names),
        "n_test": len(y_test),
    }
    print(json.dumps(overall, indent=2))

    print("\nPer-class F1 (sorted, lowest first -- these are the hardest attack types to distinguish):")
    per_class_f1 = sorted(
        [(cn, report[cn]["f1-score"], int(report[cn]["support"])) for cn in class_names],
        key=lambda x: x[1])
    for cn, f1, support in per_class_f1:
        print(f"  {cn:25s} F1={f1:.3f}  (n={support})")

    with open(RESULTS_PATH, "w") as f:
        json.dump({"overall": overall, "per_class": report}, f, indent=2)
    print(f"\nSaved -> {RESULTS_PATH}")


if __name__ == "__main__":
    main()
