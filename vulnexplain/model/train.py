"""Fine-tune GraphCodeBERT Multi-Task Model for Vulnerability and CWE Detection.

Optimized for NVIDIA RTX 4050 (6GB VRAM), Google Colab T4, and Local Acceleration.
Includes:
- Warm-starting from pretrained checkpoints (--pretrained_checkpoint / --pretrained_model)
- Differential learning rates (encoder vs classification heads)
- Cosine Annealing with warmup & gradient clipping for higher accuracy
- Gradient accumulation & FP16 mixed precision for 6GB VRAM GPU safety
"""

import argparse
import json
import os
import random
import sys
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.metrics import f1_score, precision_score, recall_score, accuracy_score
import torch
import torch.nn as nn
from torch.utils.data import Dataset, DataLoader
from transformers import (
    AutoTokenizer,
    AutoModel,
    get_cosine_schedule_with_warmup,
    get_linear_schedule_with_warmup,
)

# Add current directory for config import
sys.path.append(str(Path(__file__).resolve().parent))
from config import (
    MODEL_NAME,
    MAX_SEQ_LENGTH,
    BATCH_SIZE,
    LEARNING_RATE,
    NUM_EPOCHS,
    WEIGHT_DECAY,
    RANDOM_SEED,
    CWE_LOSS_WEIGHT,
    PROCESSED_DATA_DIR,
    CHECKPOINTS_DIR,
    BEST_MODEL_DIR,
    RESULTS_DIR,
    get_device,
)


def set_seed(seed: int = 42):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)
    if torch.cuda.is_available():
        torch.cuda.manual_seed_all(seed)
        torch.backends.cudnn.deterministic = True
        torch.backends.cudnn.benchmark = False


class CodeVulnerabilityDataset(Dataset):
    """PyTorch Dataset for multi-task code classification."""

    def __init__(self, df: pd.DataFrame, tokenizer, cwe_map: dict[str, int], max_len: int = 512):
        self.codes = df["code"].astype(str).tolist()
        self.labels = df["label"].astype(int).tolist()
        self.cwes = df["cwe"].astype(str).tolist()
        self.tokenizer = tokenizer
        self.cwe_map = cwe_map
        self.max_len = max_len
        self.other_cwe_idx = cwe_map.get("OTHER", len(cwe_map) - 1)

    def __len__(self):
        return len(self.codes)

    def __getitem__(self, idx: int):
        code_str = self.codes[idx]
        vuln_label = self.labels[idx]
        cwe_str = self.cwes[idx]

        # Map CWE
        cwe_label = self.cwe_map.get(cwe_str, self.other_cwe_idx)

        # Tokenize code
        encoding = self.tokenizer(
            code_str,
            max_length=self.max_len,
            padding="max_length",
            truncation=True,
            return_tensors="pt",
        )

        return {
            "input_ids": encoding["input_ids"].squeeze(0),
            "attention_mask": encoding["attention_mask"].squeeze(0),
            "label": torch.tensor(vuln_label, dtype=torch.float),
            "cwe": torch.tensor(cwe_label, dtype=torch.long),
        }


class VulnGraphCodeBERT(nn.Module):
    """GraphCodeBERT encoder with dual classification heads:

    1. Binary vulnerability head: [CLS] -> Linear -> 1 logit
    2. CWE category head: [CLS] -> Linear -> num_cwe logits
    """

    def __init__(self, model_name_or_path: str, num_cwe_classes: int):
        super().__init__()
        print(f"Loading pretrained backbone from: {model_name_or_path}")
        self.encoder = AutoModel.from_pretrained(model_name_or_path)
        hidden_size = self.encoder.config.hidden_size

        self.dropout = nn.Dropout(0.2)
        # Binary Vulnerability Head
        self.vuln_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size // 2, 1),
        )
        # CWE Multi-class Head
        self.cwe_head = nn.Sequential(
            nn.Linear(hidden_size, hidden_size // 2),
            nn.GELU(),
            nn.Dropout(0.2),
            nn.Linear(hidden_size // 2, num_cwe_classes),
        )

    def forward(self, input_ids, attention_mask):
        outputs = self.encoder(input_ids=input_ids, attention_mask=attention_mask)
        # Take the [CLS] token representation (first token)
        cls_rep = outputs.last_hidden_state[:, 0, :]
        cls_rep = self.dropout(cls_rep)

        vuln_logits = self.vuln_head(cls_rep).squeeze(-1)
        cwe_logits = self.cwe_head(cls_rep)

        return vuln_logits, cwe_logits


def tune_threshold(y_true: list[int], y_probs: list[float]) -> tuple[float, float]:
    """Scans decision threshold from 0.1 to 0.9 to maximize validation F1."""
    best_thresh = 0.5
    best_f1 = -1.0

    thresholds = np.linspace(0.1, 0.9, 17)
    for t in thresholds:
        preds = [1 if p >= t else 0 for p in y_probs]
        score = f1_score(y_true, preds, zero_division=0)
        if score > best_f1:
            best_f1 = score
            best_thresh = float(round(t, 2))

    return best_thresh, best_f1


def train_model(
    sample_n: int | None = None,
    epochs: int = NUM_EPOCHS,
    batch_size: int = BATCH_SIZE,
    max_len: int = MAX_SEQ_LENGTH,
    pretrained_model: str = MODEL_NAME,
    pretrained_checkpoint: str | None = None,
    grad_accum_steps: int = 1,
    lr: float = LEARNING_RATE,
    patience: int | None = None,
):
    set_seed(RANDOM_SEED)
    device = get_device()
    print(f"Using computing device: {device}")
    if device.type == "cuda":
        gpu_name = torch.cuda.get_device_name(0)
        vram_gb = torch.cuda.get_device_properties(0).total_memory / (1024**3)
        print(f"CUDA Device: {gpu_name} ({vram_gb:.2f} GB VRAM)")
        if "4050" in gpu_name:
            print("Detected NVIDIA RTX 4050: Applying Ada Lovelace FP16 Tensor Core acceleration.")

    report_path = RESULTS_DIR / "preprocessing_report.json"
    if not report_path.exists():
        raise RuntimeError("Run model/prepare_data.py before training/evaluation.")
    report = json.loads(report_path.read_text(encoding="utf-8"))
    if report.get("status") != "ready" or report.get("training_source") != "cvefixes":
        raise RuntimeError("Data preparation is incomplete; inspect results/preprocessing_report.json.")

    # 1. Load Parquet Data
    train_path = PROCESSED_DATA_DIR / "cvefixes_train.parquet"
    val_path = PROCESSED_DATA_DIR / "cvefixes_val.parquet"

    if not train_path.exists() or not val_path.exists():
        print("ERROR: Processed parquet data not found. Please run prepare_data.py first!")
        sys.exit(1)

    train_df = pd.read_parquet(train_path)
    val_df = pd.read_parquet(val_path)

    if sample_n:
        train_df = train_df.head(sample_n)
        val_df = val_df.head(max(20, sample_n // 5))
        print(f"Running on sample subset: Train={len(train_df)}, Val={len(val_df)}")

    # 2. Load CWE Map
    cwe_map_path = CHECKPOINTS_DIR / "cwe_map.json"
    if not cwe_map_path.exists():
        cwe_map_path = BEST_MODEL_DIR / "cwe_map.json"
    with open(cwe_map_path, "r", encoding="utf-8") as f:
        cwe_map = json.load(f)
    num_cwes = len(cwe_map)

    # 3. Compute class weights for imbalance
    vuln_count = (train_df["label"] == 1).sum()
    safe_count = (train_df["label"] == 0).sum()
    pos_weight_val = safe_count / max(1, vuln_count)
    pos_weight = torch.tensor([pos_weight_val], device=device)
    print(f"Class distribution: Safe={safe_count}, Vuln={vuln_count} (pos_weight: {pos_weight_val:.2f})")

    # 4. Tokenizer & Dataloaders
    print(f"Loading tokenizer for: {pretrained_model}...")
    tokenizer = AutoTokenizer.from_pretrained(pretrained_model)

    train_dataset = CodeVulnerabilityDataset(train_df, tokenizer, cwe_map, max_len=max_len)
    val_dataset = CodeVulnerabilityDataset(val_df, tokenizer, cwe_map, max_len=max_len)

    pin_mem = device.type == "cuda"
    train_loader = DataLoader(
        train_dataset,
        batch_size=batch_size,
        shuffle=True,
        drop_last=False,
        pin_memory=pin_mem,
    )
    val_loader = DataLoader(
        val_dataset,
        batch_size=batch_size,
        shuffle=False,
        pin_memory=pin_mem,
    )

    # 5. Model Initialization & Pretrained Checkpoint Loading
    print(f"Initializing VulnGraphCodeBERT ({num_cwes} CWE categories)...")
    model = VulnGraphCodeBERT(pretrained_model, num_cwe_classes=num_cwes)

    # Option to load previously trained checkpoint weights (Warm Start)
    if pretrained_checkpoint and os.path.exists(pretrained_checkpoint):
        print(f"--> Warm-starting from existing checkpoint: {pretrained_checkpoint}")
        state_dict = torch.load(pretrained_checkpoint, map_location="cpu")
        model.load_state_dict(state_dict, strict=False)
        print("--> Pretrained checkpoint weights successfully loaded!")
    elif (BEST_MODEL_DIR / "pytorch_model.bin").exists() and pretrained_checkpoint == "auto":
        print(f"--> Auto-loading existing best checkpoint from {BEST_MODEL_DIR / 'pytorch_model.bin'}")
        state_dict = torch.load(BEST_MODEL_DIR / "pytorch_model.bin", map_location="cpu")
        model.load_state_dict(state_dict, strict=False)

    model.to(device)

    # Loss functions
    bce_loss_fn = nn.BCEWithLogitsLoss(pos_weight=pos_weight)
    ce_loss_fn = nn.CrossEntropyLoss()

    # 6. Differential Learning Rate: Lower for backbone, higher for classification heads
    no_decay = ["bias", "LayerNorm.weight"]
    encoder_params = [
        {
            "params": [p for n, p in model.encoder.named_parameters() if not any(nd in n for nd in no_decay)],
            "weight_decay": WEIGHT_DECAY,
            "lr": lr,
        },
        {
            "params": [p for n, p in model.encoder.named_parameters() if any(nd in n for nd in no_decay)],
            "weight_decay": 0.0,
            "lr": lr,
        },
    ]
    # Heads receive 2.5x learning rate for rapid feature adaptation
    head_params = [
        {
            "params": list(model.vuln_head.parameters()) + list(model.cwe_head.parameters()),
            "weight_decay": WEIGHT_DECAY,
            "lr": lr * 2.5,
        }
    ]

    optimizer = torch.optim.AdamW(encoder_params + head_params)

    total_update_steps = ((len(train_loader) + grad_accum_steps - 1) // grad_accum_steps) * epochs
    warmup_steps = int(total_update_steps * 0.1)
    scheduler = get_cosine_schedule_with_warmup(
        optimizer,
        num_warmup_steps=warmup_steps,
        num_training_steps=max(1, total_update_steps),
    )

    # FP16 Automatic Mixed Precision
    scaler = torch.cuda.amp.GradScaler() if device.type == "cuda" else None

    # Tracking metrics
    best_val_f1 = -1.0
    best_threshold = 0.50
    epochs_no_improve = 0
    training_logs = []
    BEST_MODEL_DIR.mkdir(parents=True, exist_ok=True)
    RESULTS_DIR.mkdir(parents=True, exist_ok=True)

    effective_batch = batch_size * grad_accum_steps
    print(f"\n>>> Starting Training Loop:")
    print(f"    Epochs: {epochs} | Batch Size: {batch_size} (Grad Accum: {grad_accum_steps} -> Effective: {effective_batch})")
    print(f"    Encoder LR: {lr:.2e} | Heads LR: {lr * 2.5:.2e} | Max Token Length: {max_len}")

    for epoch in range(1, epochs + 1):
        model.train()
        total_train_loss = 0.0
        optimizer.zero_grad()

        for step, batch in enumerate(train_loader):
            input_ids = batch["input_ids"].to(device, non_blocking=pin_mem)
            attention_mask = batch["attention_mask"].to(device, non_blocking=pin_mem)
            labels = batch["label"].to(device, non_blocking=pin_mem)
            cwes = batch["cwe"].to(device, non_blocking=pin_mem)

            if scaler is not None:
                with torch.cuda.amp.autocast():
                    vuln_logits, cwe_logits = model(input_ids, attention_mask)
                    vuln_loss = bce_loss_fn(vuln_logits, labels)

                    # CWE loss only on vulnerable samples (labels == 1)
                    vuln_mask = labels == 1
                    if vuln_mask.sum() > 0:
                        cwe_loss = ce_loss_fn(cwe_logits[vuln_mask], cwes[vuln_mask])
                    else:
                        cwe_loss = torch.tensor(0.0, device=device)

                    loss = (vuln_loss + (CWE_LOSS_WEIGHT * cwe_loss)) / grad_accum_steps

                scaler.scale(loss).backward()

                if (step + 1) % grad_accum_steps == 0 or (step + 1) == len(train_loader):
                    scaler.unscale_(optimizer)
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                    scaler.step(optimizer)
                    scaler.update()
                    optimizer.zero_grad()
                    scheduler.step()
            else:
                vuln_logits, cwe_logits = model(input_ids, attention_mask)
                vuln_loss = bce_loss_fn(vuln_logits, labels)

                vuln_mask = labels == 1
                if vuln_mask.sum() > 0:
                    cwe_loss = ce_loss_fn(cwe_logits[vuln_mask], cwes[vuln_mask])
                else:
                    cwe_loss = torch.tensor(0.0, device=device)

                loss = (vuln_loss + (CWE_LOSS_WEIGHT * cwe_loss)) / grad_accum_steps
                loss.backward()

                if (step + 1) % grad_accum_steps == 0 or (step + 1) == len(train_loader):
                    torch.nn.utils.clip_grad_norm_(model.parameters(), max_norm=1.0)
                    optimizer.step()
                    optimizer.zero_grad()
                    scheduler.step()

            total_train_loss += loss.item() * grad_accum_steps

            if (step + 1) % max(1, len(train_loader) // 5) == 0 or (step + 1) == len(train_loader):
                print(f"Epoch {epoch}/{epochs} | Step {step+1}/{len(train_loader)} | Loss: {loss.item() * grad_accum_steps:.4f}")

        avg_train_loss = total_train_loss / len(train_loader)

        # Validation Phase
        model.eval()
        val_labels = []
        val_probs = []

        with torch.no_grad():
            for batch in val_loader:
                input_ids = batch["input_ids"].to(device, non_blocking=pin_mem)
                attention_mask = batch["attention_mask"].to(device, non_blocking=pin_mem)
                labels = batch["label"].to(device, non_blocking=pin_mem)

                if scaler is not None:
                    with torch.cuda.amp.autocast():
                        vuln_logits, _ = model(input_ids, attention_mask)
                else:
                    vuln_logits, _ = model(input_ids, attention_mask)

                probs = torch.sigmoid(vuln_logits)
                val_labels.extend(labels.cpu().numpy().tolist())
                val_probs.extend(probs.cpu().numpy().tolist())

        val_thresh, val_f1 = tune_threshold(val_labels, val_probs)
        preds = [1 if p >= val_thresh else 0 for p in val_probs]
        val_acc = accuracy_score(val_labels, preds)
        val_prec = precision_score(val_labels, preds, zero_division=0)
        val_rec = recall_score(val_labels, preds, zero_division=0)

        print(
            f"\n[Validation Epoch {epoch}] Loss: {avg_train_loss:.4f} | "
            f"F1: {val_f1:.4f} | Acc: {val_acc:.4f} | Prec: {val_prec:.4f} | Rec: {val_rec:.4f} | Opt Threshold: {val_thresh}"
        )

        training_logs.append({
            "epoch": epoch,
            "train_loss": round(avg_train_loss, 4),
            "val_f1": round(val_f1, 4),
            "val_accuracy": round(val_acc, 4),
            "val_precision": round(val_prec, 4),
            "val_recall": round(val_rec, 4),
            "optimal_threshold": val_thresh,
        })
        pd.DataFrame(training_logs).to_csv(RESULTS_DIR / "training_log.csv", index=False)

        # Save Best Checkpoint by Validation F1
        if val_f1 > best_val_f1:
            best_val_f1 = val_f1
            best_threshold = val_thresh
            epochs_no_improve = 0
            print(f"*** New best checkpoint at Epoch {epoch} (F1: {val_f1:.4f}). Saving to {BEST_MODEL_DIR}...")

            # Save model weights binary format
            torch.save(model.state_dict(), BEST_MODEL_DIR / "pytorch_model.bin")
            # Save tokenizer files
            tokenizer.save_pretrained(BEST_MODEL_DIR)
            # Save CWE Map
            with open(BEST_MODEL_DIR / "cwe_map.json", "w", encoding="utf-8") as f:
                json.dump(cwe_map, f, indent=2)
            # Save Threshold & best metric
            with open(BEST_MODEL_DIR / "threshold.json", "w", encoding="utf-8") as f:
                json.dump({"threshold": best_threshold, "best_val_f1": best_val_f1}, f, indent=2)
        else:
            epochs_no_improve += 1
            if patience and epochs_no_improve >= patience:
                print(f"\n[Early Stopping] Validation F1 has not improved for {patience} consecutive epochs. Stopping early at Epoch {epoch} to prevent overfitting.")
                break

    # Save training log CSV
    log_df = pd.DataFrame(training_logs)
    log_path = RESULTS_DIR / "training_log.csv"
    log_df.to_csv(log_path, index=False)
    print(f"\nTraining log saved to: {log_path}")
    print(f"Best Model preserved at: {BEST_MODEL_DIR} with decision threshold: {best_threshold}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VulnExplain GraphCodeBERT Training Script (RTX 4050 / GPU Optimized)")
    parser.add_argument("--sample", type=int, default=None, help="Debug with N samples")
    parser.add_argument("--epochs", type=int, default=NUM_EPOCHS, help="Number of training epochs")
    parser.add_argument("--batch_size", type=int, default=BATCH_SIZE, help="Batch size (use 8 for 6GB RTX 4050)")
    parser.add_argument("--grad_accum", type=int, default=1, help="Gradient accumulation steps (use 2 for RTX 4050)")
    parser.add_argument("--max_len", type=int, default=MAX_SEQ_LENGTH, help="Maximum token length (<= 512)")
    parser.add_argument("--lr", type=float, default=LEARNING_RATE, help="Learning rate for encoder backbone")
    parser.add_argument("--pretrained_model", type=str, default=MODEL_NAME, help="Pretrained model identifier or path")
    parser.add_argument("--pretrained_checkpoint", type=str, default=None, help="Path to checkpoint weights (.bin/.pt) to warm-start training")
    parser.add_argument("--patience", type=int, default=7, help="Early stopping patience (epochs without validation F1 improvement, 0 to disable)")
    args = parser.parse_args()

    patience_val = args.patience if args.patience > 0 else None

    train_model(
        sample_n=args.sample,
        epochs=args.epochs,
        batch_size=args.batch_size,
        max_len=args.max_len,
        pretrained_model=args.pretrained_model,
        pretrained_checkpoint=args.pretrained_checkpoint,
        grad_accum_steps=args.grad_accum,
        lr=args.lr,
        patience=patience_val,
    )
