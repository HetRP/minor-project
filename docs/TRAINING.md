# VulnExplain — Model Training & GPU Acceleration Guide

This document details how to train and fine-tune the multi-task **GraphCodeBERT** model, with special optimization for the **NVIDIA GeForce RTX 4050 Laptop/Desktop GPU (6GB VRAM)** as well as Google Colab and Kaggle.

---

## 1. Hardware Architecture & VRAM Budget (NVIDIA RTX 4050)

The **NVIDIA GeForce RTX 4050** is based on NVIDIA's **Ada Lovelace architecture** (AD107 core) featuring:
- **6 GB GDDR6 VRAM** (96-bit memory bus)
- **2,560 CUDA Cores**
- **80 4th-Gen Tensor Cores** supporting hardware-accelerated **FP16** and **BF16** mixed precision
- **CUDA Compute Capability 8.9**

### VRAM Budget Analysis for GraphCodeBERT Fine-Tuning:
```
+------------------------------------+--------------------------+
| Component                          | VRAM Footprint           |
+------------------------------------+--------------------------+
| Model Weights (FP16)               | ~ 250 MB                 |
| Gradients (FP16)                   | ~ 250 MB                 |
| Optimizer States (AdamW)           | ~ 500 MB                 |
| Activations (Batch 8, SeqLen 512)  | ~ 3.4 GB                 |
| PyTorch Workspace & CUDA Overhead  | ~ 0.5 GB                 |
+------------------------------------+--------------------------+
| Total Peak Memory Utilization      | ~ 4.9 GB / 6.0 GB (SAFE) |
+------------------------------------+--------------------------+
```
> [!TIP]
> By configuring `--batch_size 8` with `--grad_accum 2`, the model achieves an **effective batch size of 16** (identical optimization dynamics to an enterprise 16GB GPU) while staying strictly under the 6GB VRAM ceiling of the RTX 4050.

---

## 2. NVIDIA RTX 4050 Setup Guide

### Step 1: Install CUDA-Enabled PyTorch
To utilize your RTX 4050 Tensor Cores, you must install the CUDA build of PyTorch:

```bash
# For CUDA 12.1 (Recommended for modern NVIDIA drivers):
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu121

# Or for CUDA 11.8:
pip install torch torchvision --index-url https://download.pytorch.org/whl/cu118
```

### Step 2: Verify GPU Detection
Run this one-line command in your terminal to ensure your RTX 4050 is recognized:

```bash
python -c "import torch; print('CUDA Available:', torch.cuda.is_available(), '| Device Name:', torch.cuda.get_device_name(0), '| VRAM:', round(torch.cuda.get_device_properties(0).total_memory / (1024**3), 2), 'GB')"
```
**Expected Output:**
```
CUDA Available: True | Device Name: NVIDIA GeForce RTX 4050 Laptop GPU | VRAM: 6.0 GB
```

---

## 3. Increasing Accuracy via Pretrained Models & Warm Starts

VulnExplain supports multiple techniques to maximize vulnerability detection accuracy:

1. **Pretrained Code-Intelligence Backbone:**
   - Backbone: `microsoft/graphcodebert-base` (pre-trained on multilingual code corpora and semantic data flows).
2. **Warm-Starting / Checkpoint Resumption (`--pretrained_checkpoint`):**
   - You can initialize training from any previously saved checkpoint (e.g. `model/checkpoints/best/pytorch_model.bin`) or a specialized security model checkpoint.
   - Command:
     ```bash
     python model/train.py --pretrained_checkpoint model/checkpoints/best/pytorch_model.bin --epochs 2 --lr 1e-5
     ```
3. **Differential Learning Rates:**
   - The encoder backbone is fine-tuned gently (`lr = 1.5e-5`) to preserve universal code representations.
   - The classification heads receive 2.5× higher learning rate (`lr = 3.75e-5`) for rapid convergence on decision boundaries.
4. **Cosine Annealing with Warmup:**
   - Smooth cosine decay schedule after a 10% linear warmup phase avoids local minima and stabilizes validation F1.
5. **Gradient Clipping:**
   - Norm clipped to $1.0$ to prevent gradient explosion on long function samples.

---

## 4. Run Everything at Once on NVIDIA RTX 4050

You can run the entire pipeline end-to-end on your RTX 4050 with the following sequential commands:

### Command Sequence:

```bash
# Step 1: Inspect raw datasets
python model/inspect_dataset.py

# Step 2: Prepare Parquet datasets (GroupShuffleSplit by project)
# (Add --generate-synthetic if you haven't downloaded raw datasets yet)
python model/prepare_data.py

# Step 3: Train GraphCodeBERT on RTX 4050 with FP16 Tensor Cores
python model/train.py --batch_size 8 --grad_accum 2 --epochs 3 --max_len 512

# Step 4: Run full evaluation & generate all metrics and plots
python model/evaluate.py
```

### Or Run via Automated Runner Scripts:
- **Windows:** Double-click or run `scripts/run_pipeline_rtx4050.bat`
- **Linux / WSL2:** Run `bash scripts/run_pipeline_rtx4050.sh`

---

## 5. In-Depth: Where and How Everything is Saved

All outputs follow standardized, deterministic storage formats:

### 5.1 Processed Datasets (`data/processed/`)
| File | Format | Description |
| :--- | :--- | :--- |
| `reef_train.parquet` | Apache Parquet (Snappy) | 80% train split. Columns: `id, code, label, language, cwe, project, commit_date`. |
| `reef_val.parquet` | Apache Parquet (Snappy) | 10% validation split from disjoint projects. |
| `reef_test.parquet` | Apache Parquet (Snappy) | 10% in-distribution test split from disjoint projects. |
| `cvefixes_functions.parquet`| Apache Parquet (Snappy) | Cleaned external test set (all samples appearing in train are removed). |

### 5.2 Model Checkpoints (`model/checkpoints/best/`)
| File | Format | Content & Purpose |
| :--- | :--- | :--- |
| `pytorch_model.bin` | PyTorch Binary State Dict | Serialized neural network weights saved via `torch.save(model.state_dict(), ...)`. Size: ~490 MB. |
| `cwe_map.json` | JSON dictionary | Mapping of top 20 CWE names to output neuron indices (`{"CWE-78": 0, "CWE-89": 1, ..., "OTHER": 20}`). |
| `threshold.json` | JSON dictionary | Optimal decision threshold tuned on validation set (`{"threshold": 0.52, "best_val_f1": 0.841}`). |
| `tokenizer.json`<br>`vocab.json`<br>`merges.txt` | HuggingFace Tokenizer | Byte-Pair Encoding (BPE) subword vocabulary for tokenizing C, C++, C#, Go, Java, JS, and Python. |

### 5.3 Results & Visualizations (`results/`)
| File | Format | Description |
| :--- | :--- | :--- |
| `training_log.csv` | CSV | Epoch number, training loss, validation F1, precision, recall, and optimal threshold per epoch. |
| `metrics_overall.json` | JSON | Key metrics (Accuracy, Precision, Recall, F1, MCC, ROC-AUC, PR-AUC) for both REEF-test and CVEfixes external. |
| `metrics_by_language.csv` | CSV | Evaluation breakdown across all 7 programming languages. |
| `metrics_by_cwe.csv` | CSV | Recall rates for each of the top 20 CWE vulnerability types. |
| `roc_curve.png` | 200 DPI PNG Plot | ROC curve comparing REEF-test vs CVEfixes external set. |
| `pr_curve.png` | 200 DPI PNG Plot | Precision-Recall curve under class imbalance. |
| `confusion_matrix.png` | 200 DPI PNG Plot | True Positive / True Negative / False Positive / False Negative counts. |
| `false_positives.csv` | CSV | Top 50 false positives with probability and first 300 characters of code. |
| `false_negatives.csv` | CSV | Top 50 false negatives with probability and first 300 characters of code. |
| `performance_by_length.csv`| CSV | Metrics categorized by code length bucket: short (<200 chars), medium (200-800), long (>800). |
| `summary.md` | Markdown | Formatted summary tables ready to insert directly into research papers or reports. |

---

## 6. Cloud Alternatives (Google Colab / Kaggle)

If you ever need to train without your RTX 4050:
- **Google Colab (T4 GPU):**
  ```bash
  !pip install -r requirements.txt
  !python model/prepare_data.py
  !python model/train.py --batch_size 16 --epochs 3
  !python model/evaluate.py
  ```
- **Kaggle Notebooks (P100 / T4):**
  Select **GPU P100** accelerator and run the same commands.
