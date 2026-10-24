"""Comprehensive Evaluation & Metric Generation for VulnExplain.

Evaluates best GraphCodeBERT checkpoint on:
1. REEF Test Set (in-distribution, project-disjoint)
2. CVEfixes External Set (out-of-distribution external benchmark)

Outputs:
- results/metrics_overall.json
- results/metrics_by_language.csv
- results/metrics_by_cwe.csv
- results/false_positives.csv
- results/false_negatives.csv
- results/performance_by_length.csv
- results/roc_curve.png
- results/pr_curve.png
- results/confusion_matrix.png
- results/summary.md
"""

import argparse
import json
import os
import sys
from contextlib import nullcontext
import time
import hashlib
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import pyarrow.parquet as pq
from sklearn.metrics import (
    accuracy_score,
    precision_score,
    recall_score,
    f1_score,
    matthews_corrcoef,
    roc_auc_score,
    roc_curve,
    precision_recall_curve,
    auc,
    confusion_matrix,
    classification_report,
)
import torch
import torch.nn as nn
from torch.utils.data import DataLoader
from transformers import AutoTokenizer

sys.path.append(str(Path(__file__).resolve().parent))
from config import (
    MODEL_NAME,
    MAX_SEQ_LENGTH,
    PROCESSED_DATA_DIR,
    BEST_MODEL_DIR,
    RESULTS_DIR,
    SUPPORTED_LANGUAGES,
    get_device,
    file_sha256,
)
from train import VulnGraphCodeBERT, CodeVulnerabilityDataset, tokenize_code

def predict_parquet(path,model,tokenizer,cwe_map,device,max_len,batch_size):
    """Read one source function at a time; batch only fixed-size token tensors."""
    inverse={v:k for k,v in cwe_map.items()}
    truth=[]; probabilities=[]; cwes=[]; pending=[]; labels=[]
    def flush():
        if not pending: return
        ids=torch.cat([e['input_ids'] for e in pending]).to(device)
        mask=torch.cat([e['attention_mask'] for e in pending]).to(device)
        with torch.inference_mode():
            with torch.amp.autocast('cuda') if device.type=='cuda' else nullcontext():
                binary,categories=model(ids,mask)
        probabilities.extend(torch.sigmoid(binary.float()).cpu().tolist())
        cwes.extend(inverse[int(i)] for i in categories.argmax(-1).cpu().tolist())
        truth.extend(labels); pending.clear(); labels.clear()
        if len(truth)%1000<batch_size: print(f'External evaluation: {len(truth)} functions',flush=True)
    model.eval()
    for batch in pq.ParquetFile(path).iter_batches(batch_size=1,columns=['code','label']):
        row=batch.to_pylist()[0]
        pending.append(tokenize_code(tokenizer,row['code'],max_len)); labels.append(int(row['label']))
        if len(pending)>=batch_size: flush()
    flush()
    return truth,probabilities,cwes


def compute_metrics(y_true: list[int], y_probs: list[float], threshold: float = 0.5) -> dict[str, float]:
    """Computes full suite of classification metrics."""
    y_true = np.array(y_true)
    y_probs = np.array(y_probs)
    preds = (y_probs >= threshold).astype(int)

    acc = accuracy_score(y_true, preds)
    prec = precision_score(y_true, preds, zero_division=0)
    rec = recall_score(y_true, preds, zero_division=0)
    f1 = f1_score(y_true, preds, zero_division=0)
    mcc = matthews_corrcoef(y_true, preds) if len(np.unique(y_true)) > 1 else 0.0

    # ROC-AUC & PR-AUC
    try:
        roc_val = roc_auc_score(y_true, y_probs) if len(np.unique(y_true)) > 1 else 0.5
        p_curve, r_curve, _ = precision_recall_curve(y_true, y_probs)
        pr_val = auc(r_curve, p_curve)
    except Exception:
        roc_val = 0.5
        pr_val = 0.0

    return {
        "accuracy": round(float(acc), 4),
        "precision": round(float(prec), 4),
        "recall": round(float(rec), 4),
        "f1": round(float(f1), 4),
        "mcc": round(float(mcc), 4),
        "roc_auc": round(float(roc_val), 4),
        "pr_auc": round(float(pr_val), 4),
    }


def predict_dataset(df: pd.DataFrame, model, tokenizer, cwe_map: dict[str, int], device, max_len: int = 512, batch_size: int = 4):
    """Runs inference across dataframe and extracts probabilities and predicted CWEs."""
    if df.empty:
        return [], [], []

    inv_cwe_map = {v: k for k, v in cwe_map.items()}

    # Check if model is dummy or None (for dry evaluation)
    if model is None:
        raise RuntimeError('Real trained checkpoint required; mock predictions forbidden')

    dataset = CodeVulnerabilityDataset(df, tokenizer, cwe_map, max_len=max_len)
    loader = DataLoader(dataset, batch_size=batch_size, shuffle=False)

    y_true = []
    y_probs = []
    pred_cwes = []

    model.eval()
    with torch.no_grad():
        for batch in loader:
            input_ids = batch["input_ids"].to(device)
            attention_mask = batch["attention_mask"].to(device)
            labels = batch["label"].to(device)

            with torch.amp.autocast('cuda') if device.type=='cuda' else nullcontext():
                vuln_logits, cwe_logits = model(input_ids, attention_mask)
            probs = torch.sigmoid(vuln_logits.float())
            cwe_preds = torch.argmax(cwe_logits, dim=-1)

            y_true.extend(labels.cpu().numpy().tolist())
            y_probs.extend(probs.cpu().numpy().tolist())
            for idx in cwe_preds.cpu().numpy().tolist():
                pred_cwes.append(inv_cwe_map.get(idx, "OTHER"))

    return [int(y) for y in y_true], [float(p) for p in y_probs], pred_cwes


def plot_roc_pr_and_cm(reef_true, reef_probs, reef_preds, cve_true, cve_probs, results_dir: Path):
    """Generates ROC, PR, and Confusion Matrix plots."""
    results_dir.mkdir(parents=True, exist_ok=True)

    # 1. ROC Curve
    plt.figure(figsize=(7, 5))
    if len(np.unique(reef_true)) > 1:
        fpr, tpr, _ = roc_curve(reef_true, reef_probs)
        roc_auc_val = auc(fpr, tpr)
        plt.plot(fpr, tpr, color="blue", lw=2, label=f"REEF Test (AUC = {roc_auc_val:.3f})")

    if cve_true and len(np.unique(cve_true)) > 1:
        fpr_c, tpr_c, _ = roc_curve(cve_true, cve_probs)
        roc_auc_cve = auc(fpr_c, tpr_c)
        plt.plot(fpr_c, tpr_c, color="red", lw=2, linestyle="--", label=f"CVEfixes External (AUC = {roc_auc_cve:.3f})")

    plt.plot([0, 1], [0, 1], color="gray", linestyle=":")
    plt.xlabel("False Positive Rate")
    plt.ylabel("True Positive Rate")
    plt.title("Receiver Operating Characteristic (ROC)")
    plt.legend(loc="lower right")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(results_dir / "roc_curve.png", dpi=200)
    plt.close()

    # 2. PR Curve
    plt.figure(figsize=(7, 5))
    if len(np.unique(reef_true)) > 1:
        prec, rec, _ = precision_recall_curve(reef_true, reef_probs)
        pr_auc_val = auc(rec, prec)
        plt.plot(rec, prec, color="blue", lw=2, label=f"REEF Test (PR-AUC = {pr_auc_val:.3f})")

    if cve_true and len(np.unique(cve_true)) > 1:
        prec_c, rec_c, _ = precision_recall_curve(cve_true, cve_probs)
        pr_auc_cve = auc(rec_c, prec_c)
        plt.plot(rec_c, prec_c, color="red", lw=2, linestyle="--", label=f"CVEfixes External (PR-AUC = {pr_auc_cve:.3f})")

    plt.xlabel("Recall")
    plt.ylabel("Precision")
    plt.title("Precision-Recall Curve")
    plt.legend(loc="lower left")
    plt.grid(True, alpha=0.3)
    plt.tight_layout()
    plt.savefig(results_dir / "pr_curve.png", dpi=200)
    plt.close()

    # 3. Confusion Matrix (REEF Test)
    plt.figure(figsize=(5, 4))
    cm = confusion_matrix(reef_true, reef_preds)
    plt.imshow(cm, interpolation="nearest", cmap=plt.cm.Blues)
    plt.title("Confusion Matrix (REEF Test)")
    plt.colorbar()
    tick_marks = np.arange(2)
    plt.xticks(tick_marks, ["Safe (0)", "Vuln (1)"])
    plt.yticks(tick_marks, ["Safe (0)", "Vuln (1)"])

    for i in range(cm.shape[0]):
        for j in range(cm.shape[1]):
            plt.text(j, i, format(cm[i, j], "d"),
                     horizontalalignment="center",
                     color="white" if cm[i, j] > cm.max() / 2 else "black")

    plt.ylabel("True Label")
    plt.xlabel("Predicted Label")
    plt.tight_layout()
    plt.savefig(results_dir / "confusion_matrix.png", dpi=200)
    plt.close()


def run_evaluation(pretrained_model: str = MODEL_NAME, batch_size: int = 4):
    started=time.monotonic()
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)
    device = get_device()

    # 1. Load Data
    reef_test_path = PROCESSED_DATA_DIR / "reef_test.parquet"
    cvefixes_path = PROCESSED_DATA_DIR / "cvefixes_functions.parquet"

    if not reef_test_path.exists():
        print("ERROR: Processed data not found. Please run prepare_data.py first.")
        sys.exit(1)

    reef_test_df = pd.read_parquet(reef_test_path)
    cvefixes_df = pd.read_parquet(cvefixes_path,columns=['id','label','language','cwe','project','commit_date']) if cvefixes_path.exists() else pd.DataFrame()
    for name,frame in [('REEF test',reef_test_df),('CVEfixes external',cvefixes_df)]:
        if frame.empty or frame.id.str.startswith('syn_').any():
            raise ValueError(f'{name}: real nonempty dataset required')
    metadata_path=BEST_MODEL_DIR/'training_config.json'
    if not metadata_path.exists(): raise RuntimeError('Checkpoint training provenance missing')
    metadata=json.loads(metadata_path.read_text())
    if metadata.get('status')!='completed' or metadata.get('smoke_test'):
        raise RuntimeError('Full training has not completed')
    max_len=metadata['max_len']
    for name,expected in metadata.get('processed_sha256',{}).items():
        actual=file_sha256(PROCESSED_DATA_DIR/name)
        if actual!=expected: raise RuntimeError(f'Dataset changed since training: {name}')

    # 2. Load Checkpoint & Threshold
    weights_path = BEST_MODEL_DIR / "pytorch_model.bin"
    cwe_map_path = BEST_MODEL_DIR / "cwe_map.json"
    threshold_path = BEST_MODEL_DIR / "threshold.json"

    if cwe_map_path.exists():
        with open(cwe_map_path, "r", encoding="utf-8") as f:
            cwe_map = json.load(f)
    else:
        cwe_map = {"OTHER": 0}

    threshold = 0.50
    if threshold_path.exists():
        with open(threshold_path, "r", encoding="utf-8") as f:
            t_data = json.load(f)
            threshold = float(t_data.get("threshold", 0.50))
    print(f"Loaded decision threshold: {threshold}")

    model = None
    tokenizer = None

    if weights_path.exists():
        print(f"Loading best checkpoint from {BEST_MODEL_DIR}...")
        try:
            tokenizer = AutoTokenizer.from_pretrained(BEST_MODEL_DIR)
        except Exception:
            tokenizer = AutoTokenizer.from_pretrained(pretrained_model)
        model = VulnGraphCodeBERT(pretrained_model, num_cwe_classes=len(cwe_map))
        model.load_state_dict(torch.load(weights_path, map_location='cpu',weights_only=True))
        model.to(device)
    else:
        raise FileNotFoundError(weights_path)

    # 3. Predict on REEF test
    print("Evaluating on REEF Test Set...")
    reef_true, reef_probs, reef_pred_cwes = predict_dataset(reef_test_df, model, tokenizer, cwe_map, device,max_len,batch_size)
    reef_preds = [1 if p >= threshold else 0 for p in reef_probs]
    reef_metrics = compute_metrics(reef_true, reef_probs, threshold)

    # 4. Predict on CVEfixes external
    print("Evaluating on CVEfixes External Set...")
    cve_true, cve_probs, cve_pred_cwes = predict_parquet(cvefixes_path, model, tokenizer, cwe_map, device,max_len,batch_size)
    if cve_true!=cvefixes_df.label.tolist(): raise RuntimeError('External prediction ordering mismatch')
    cve_preds = [1 if p >= threshold else 0 for p in cve_probs]
    cve_metrics = compute_metrics(cve_true, cve_probs, threshold) if cve_true else {}

    # 5. Save Overall Metrics JSON
    overall_results = {
        "reef_test": reef_metrics,
        "cvefixes_external": cve_metrics,
        "threshold": threshold,
        "duration_seconds":time.monotonic()-started,
    }
    # CWE head quality on truly vulnerable samples; UNKNOWN excluded and unseen
    # known categories mapped to OTHER exactly as during training.
    cwe_reports={}
    for name,frame,predicted in [('reef_test',reef_test_df,reef_pred_cwes),('cvefixes_external',cvefixes_df,cve_pred_cwes)]:
        valid=(frame.label==1)&(frame.cwe!='UNKNOWN')
        truth=[c if c in cwe_map else 'OTHER' for c in frame.loc[valid,'cwe']]
        predictions=np.asarray(predicted)[valid.to_numpy()].tolist()
        cwe_reports[name]=dict(samples=len(truth),
            accuracy=accuracy_score(truth,predictions) if truth else None,
            macro_f1=f1_score(truth,predictions,average='macro',zero_division=0) if truth else None,
            weighted_f1=f1_score(truth,predictions,average='weighted',zero_division=0) if truth else None,
            report=classification_report(truth,predictions,zero_division=0,output_dict=True) if truth else {})
        export=frame.copy(); export['prob']=reef_probs if name=='reef_test' else cve_probs
        export['pred_cwe']=predicted
        export.drop(columns=['code'],errors='ignore').to_csv(RESULTS_DIR/(name+'_predictions.csv'),index=False)
    overall_results['cwe_classification']=cwe_reports
    with open(RESULTS_DIR / "metrics_overall.json", "w", encoding="utf-8") as f:
        json.dump(overall_results, f, indent=2)

    # 6. Breakdown by Language
    reef_test_df = reef_test_df.copy()
    reef_test_df["prob"] = reef_probs
    reef_test_df["pred"] = reef_preds
    reef_test_df["pred_cwe"] = reef_pred_cwes

    lang_metrics = []
    for lang in SUPPORTED_LANGUAGES:
        sub = reef_test_df[reef_test_df["language"] == lang]
        if not sub.empty:
            m = compute_metrics(sub["label"].tolist(), sub["prob"].tolist(), threshold)
            m["language"] = lang
            m["samples"] = len(sub)
            lang_metrics.append(m)
    lang_df = pd.DataFrame(lang_metrics)
    lang_df.to_csv(RESULTS_DIR / "metrics_by_language.csv", index=False)

    # 7. Breakdown by CWE
    cwe_metrics = []
    for cwe_name in cwe_map.keys():
        sub = reef_test_df[(reef_test_df["label"] == 1) & (reef_test_df["cwe"] == cwe_name)]
        if not sub.empty:
            rec = recall_score(sub["label"], sub["pred"], zero_division=0)
            cwe_metrics.append({
                "cwe": cwe_name,
                "vulnerable_count": len(sub),
                "detected_count": int(sub["pred"].sum()),
                "recall_rate": round(float(rec), 4),
            })
    cwe_df = pd.DataFrame(cwe_metrics)
    cwe_df.to_csv(RESULTS_DIR / "metrics_by_cwe.csv", index=False)

    # 8. Error Analysis (False Positives & False Negatives)
    fp_df = reef_test_df[(reef_test_df["label"] == 0) & (reef_test_df["pred"] == 1)].copy()
    fn_df = reef_test_df[(reef_test_df["label"] == 1) & (reef_test_df["pred"] == 0)].copy()

    for d in [fp_df, fn_df]:
        d["code_snippet"] = d["code"].astype(str).str.slice(0, 300)

    fp_export = fp_df[["id", "language", "cwe", "prob", "code_snippet"]].head(50)
    fn_export = fn_df[["id", "language", "cwe", "prob", "code_snippet"]].head(50)
    fp_export.to_csv(RESULTS_DIR / "false_positives.csv", index=False)
    fn_export.to_csv(RESULTS_DIR / "false_negatives.csv", index=False)

    # 9. Performance by Code Length Bucket
    reef_test_df["code_len"] = reef_test_df["code"].str.len()
    len_bins = [0, 200, 800, 100000]
    len_labels = ["short (<200 chars)", "medium (200-800 chars)", "long (>800 chars)"]
    reef_test_df["length_bucket"] = pd.cut(reef_test_df["code_len"], bins=len_bins, labels=len_labels)

    len_metrics = []
    for bucket in len_labels:
        sub = reef_test_df[reef_test_df["length_bucket"] == bucket]
        if not sub.empty:
            m = compute_metrics(sub["label"].tolist(), sub["prob"].tolist(), threshold)
            m["bucket"] = bucket
            m["count"] = len(sub)
            len_metrics.append(m)
    pd.DataFrame(len_metrics).to_csv(RESULTS_DIR / "performance_by_length.csv", index=False)

    # 10. Plots
    plot_roc_pr_and_cm(reef_true, reef_probs, reef_preds, cve_true, cve_probs, RESULTS_DIR)

    # 11. Generate Paper-Ready summary.md
    summary_md = f"""# VulnExplain Evaluation Summary

## Overall Performance Table
| Benchmark Dataset | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REEF Test (In-Dist)** | {reef_metrics.get('accuracy', 0):.4f} | {reef_metrics.get('precision', 0):.4f} | {reef_metrics.get('recall', 0):.4f} | **{reef_metrics.get('f1', 0):.4f}** | {reef_metrics.get('mcc', 0):.4f} | {reef_metrics.get('roc_auc', 0):.4f} | {reef_metrics.get('pr_auc', 0):.4f} |
| **CVEfixes (External)** | {cve_metrics.get('accuracy', 0):.4f} | {cve_metrics.get('precision', 0):.4f} | {cve_metrics.get('recall', 0):.4f} | **{cve_metrics.get('f1', 0):.4f}** | {cve_metrics.get('mcc', 0):.4f} | {cve_metrics.get('roc_auc', 0):.4f} | {cve_metrics.get('pr_auc', 0):.4f} |

*Tuned Decision Threshold:* `{threshold:.2f}`

## Breakdown by Programming Language (REEF Test)
{lang_df[['language', 'samples', 'accuracy', 'precision', 'recall', 'f1', 'mcc']].to_markdown(index=False) if not lang_df.empty else 'N/A'}

## Analysis of Generalization Gap
- REEF Test is project-disjoint (GroupShuffleSplit on projects), measuring generalization to unseen codebases within the same distribution.
- CVEfixes evaluates cross-dataset generalization under distribution shift (differing vulnerability discovery mechanisms and commit practices).
- MCC and PR-AUC serve as primary indicators under class imbalance.
"""

    summary_path = RESULTS_DIR / "summary.md"
    with open(summary_path, "w", encoding="utf-8") as f:
        f.write(summary_md)

    print("\n" + "=" * 60)
    print(summary_md)
    print("=" * 60)
    print(f"\nAll evaluation artifacts successfully written to: {RESULTS_DIR}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnExplain Checkpoint Evaluation Script")
    parser.add_argument("--pretrained_model", type=str, default=MODEL_NAME, help="Pretrained model identifier")
    parser.add_argument('--batch_size',type=int,default=4)
    args = parser.parse_args()
    run_evaluation(pretrained_model=args.pretrained_model,batch_size=args.batch_size)
