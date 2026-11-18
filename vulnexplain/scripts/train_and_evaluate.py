"""Unified Training & Testing Runner for VulnExplain.

Executes:
1. Multi-task GraphCodeBERT fine-tuning with 50 epochs on NVIDIA RTX 4050 GPU (FP16 mixed precision).
2. Continuous validation & best checkpoint saving.
3. Automated testing & evaluation on unseen test set (reef_test.parquet).
4. Generation of all metrics (ROC-AUC, PR-AUC, F1, MCC) and publication plots.
"""

import sys
import time
import argparse
from pathlib import Path

# Add project root and model directory to sys.path
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))
sys.path.insert(0, str(PROJECT_ROOT / "model"))

from model.train import train_model
from model.evaluate import run_evaluation
from model.config import get_device, BEST_MODEL_DIR, RESULTS_DIR


def main():
    parser = argparse.ArgumentParser(description="VulnExplain Train and Evaluate Runner")
    parser.add_argument("--epochs", type=int, default=50, help="Number of training epochs (default: 50)")
    parser.add_argument("--batch_size", type=int, default=8, help="Batch size for RTX 4050 (default: 8)")
    parser.add_argument("--grad_accum", type=int, default=2, help="Gradient accumulation steps (default: 2 -> effective batch 16)")
    parser.add_argument("--max_len", type=int, default=512, help="Max sequence length (default: 512)")
    parser.add_argument("--lr", type=float, default=2e-5, help="Learning rate (default: 2e-5)")
    parser.add_argument("--patience", type=int, default=7, help="Early stopping patience (default: 7)")
    parser.add_argument("--sample", type=int, default=None, help="Debug with sample size")
    args = parser.parse_args()

    device = get_device()
    print("=" * 80)
    print("VULNEXPLAIN: MULTI-TASK GRAPHCODEBERT TRAINING & EVALUATION PIPELINE")
    print("=" * 80)
    print(f"Device: {device}")
    if device.type == "cuda":
        import torch
        print(f"GPU Hardware: {torch.cuda.get_device_name(0)}")
        print(f"VRAM Capacity: {round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2)} GB")
        print("Hardware Acceleration: NVIDIA Ada Lovelace 4th-Gen Tensor Cores + FP16 Mixed Precision")
    print(f"Configured Epochs: {args.epochs}")
    print(f"Batch Size: {args.batch_size} (Grad Accum: {args.grad_accum} -> Effective Batch: {args.batch_size * args.grad_accum})")
    print(f"Max Token Sequence Length: {args.max_len}")
    print(f"Early Stopping Patience: {args.patience} epochs")
    print("=" * 80)

    # STEP 1: TRAINING
    t_start = time.time()
    print("\n>>> [STEP 1/2] Commencing Model Training (50 Epochs Target)...")
    train_model(
        sample_n=args.sample,
        epochs=args.epochs,
        batch_size=args.batch_size,
        max_len=args.max_len,
        grad_accum_steps=args.grad_accum,
        lr=args.lr,
        patience=args.patience if args.patience > 0 else None,
    )
    t_train = time.time() - t_start
    print(f"\n>>> [STEP 1/2 COMPLETE] Model training concluded in {t_train / 60:.1f} minutes.")
    print(f"Best checkpoint preserved at: {BEST_MODEL_DIR}")

    # STEP 2: TESTING & EVALUATION
    t_eval_start = time.time()
    print("\n>>> [STEP 2/2] Commencing Model Testing & Comprehensive Evaluation...")
    run_evaluation()
    t_eval = time.time() - t_eval_start
    print(f"\n>>> [STEP 2/2 COMPLETE] Model testing concluded in {t_eval:.1f} seconds.")

    print("\n" + "=" * 80)
    print("TRAINING & TESTING PIPELINE COMPLETE!")
    print(f"Total Elapsed Time: {(time.time() - t_start) / 60:.1f} minutes")
    print(f"Trained Checkpoint: {BEST_MODEL_DIR / 'pytorch_model.bin'}")
    print(f"Evaluation Metrics & Plots: {RESULTS_DIR}")
    print("=" * 80)


if __name__ == "__main__":
    main()

