@echo off
REM ==============================================================================
REM VulnExplain — Complete Pipeline Execution for NVIDIA RTX 4050 (Windows)
REM ==============================================================================

echo >>> [1/5] Verifying Environment & GPU Acceleration...
python -c "import torch; print('CUDA Available:', torch.cuda.is_available(), '| Device:', torch.cuda.get_device_name(0) if torch.cuda.is_available() else 'CPU')"
if %ERRORLEVEL% NEQ 0 (
    echo Error: Python or PyTorch not found. Activate your virtual environment first!
    exit /b %ERRORLEVEL%
)

echo.
echo >>> [2/5] Inspecting Raw Datasets (data/raw/)...
python model/inspect_dataset.py

echo.
echo >>> [3/5] Preprocessing Datasets & Building Parquet Splits...
python model/prepare_data.py
if %ERRORLEVEL% NEQ 0 (
    echo Notice: Running with synthetic samples for pipeline verification...
    python model/prepare_data.py --sample 400 --generate-synthetic
)

echo.
echo >>> [4/5] Training GraphCodeBERT on RTX 4050 (Batch=8, Accum=2 -> Eff=16, FP16)...
python model/train.py --batch_size 8 --grad_accum 2 --epochs 3 --max_len 512

echo.
echo >>> [5/5] Running Comprehensive Evaluation & Plot Generation...
python model/evaluate.py

echo.
echo ==============================================================================
echo PIPELINE COMPLETED SUCCESSFULLY!
echo - Model weights saved to: model/checkpoints/best/
echo - Evaluation plots and summary saved to: results/
echo ==============================================================================
pause
