#!/usr/bin/env bash
# ==============================================================================
# VulnExplain — Complete Pipeline Execution for NVIDIA RTX 4050 (Linux/WSL2/macOS)
# ==============================================================================
set -e

echo ">>> [1/5] Verifying Environment & GPU Acceleration..."
python -c "import torch; print('CUDA Available:', torch.cuda.is_available(), '| Device:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"

echo ""
echo ">>> [2/5] Inspecting Raw Datasets (data/raw/)..."
python model/inspect_dataset.py

echo ""
echo ">>> [3/5] Preprocessing Datasets & Building Parquet Splits..."
# Uses existing raw files if present, or generates realistic samples if raw data is missing
if [ ! -d "data/raw/reef" ] || [ -z "$(ls -A data/raw/reef 2>/dev/null)" ]; then
    echo "Notice: data/raw/reef is empty. Preparing dataset with synthetic multilingual samples..."
    python model/prepare_data.py --sample 400 --generate-synthetic
else
    python model/prepare_data.py
fi

echo ""
echo ">>> [4/5] Training GraphCodeBERT on RTX 4050 (Batch=8, Accum=2 -> Eff=16, FP16)..."
python model/train.py --batch_size 8 --grad_accum 2 --epochs 3 --max_len 512

echo ""
echo ">>> [5/5] Running Comprehensive Evaluation & Plot Generation..."
python model/evaluate.py

echo ""
echo "=============================================================================="
echo "PIPELINE COMPLETED SUCCESSFULLY!"
echo "- Model weights saved to: model/checkpoints/best/"
echo "- Evaluation plots and summary saved to: results/"
echo "=============================================================================="
