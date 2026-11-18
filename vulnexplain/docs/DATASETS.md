# Dataset Acquisition, Storage Formats, and Preprocessing Guide

This document provides a comprehensive, beginner-friendly guide to downloading, storing, and preprocessing the two core datasets used in VulnExplain:
1. **REEF** (Primary benchmark for training, validation, and in-distribution evaluation)
2. **CVEfixes** (External, out-of-distribution generalization benchmark)

---

## 1. Quick Reference: Dataset Specifications

| Dataset | Primary Role | Raw Save Path | Expected Raw Format | Output Processed Format | Processed Path |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **REEF** | Fine-tuning & In-Dist Test | `data/raw/reef/` | `.parquet`, `.csv`, or `.jsonl` | Apache Parquet (`.parquet`) | `data/processed/reef_train.parquet`<br>`data/processed/reef_val.parquet`<br>`data/processed/reef_test.parquet` |
| **CVEfixes** | Out-of-Distribution Validation | `data/raw/cvefixes/` | `.sqlite`, `.db`, or `.csv` | Apache Parquet (`.parquet`) | `data/processed/cvefixes_functions.parquet` |

> [!IMPORTANT]
> **Datasets NOT to Use:** Datasets like *Big-Vul* and *Devign* are **not** needed for this project. They are cited in academic literature for historical comparison only.
> **Strict Leakage Prevention:** CVEfixes is **never** used during model training. Any function whose raw code text duplicates a sample in the REEF training set is automatically identified and removed by `prepare_data.py`.

---

## 2. In-Depth Dataset Details & Download Instructions

### 2.1 REEF (Primary Training Dataset)

**Reference:** Wang et al., *"REEF: A Framework for Collecting Real-World Vulnerabilities and Fixes"*, arXiv:2309.08115.

REEF contains real-world vulnerability fixing commits across multiple programming languages with paired pre-patch (vulnerable) and post-patch (fixed) function records.

#### Where to Find the Files
1. Visit the official REEF project repository / release portal:
   - GitHub: `https://github.com/REEF-Framework/REEF`
   - Zenodo / HuggingFace Releases (as linked in the paper's README).
2. Download the function-level dataset file (typically named `reef_dataset.parquet`, `reef_functions.parquet`, or `reef.jsonl`).
3. Place the file inside:
   ```
   vulnexplain/data/raw/reef/
   ```

#### Download Commands

##### Linux / macOS / WSL2
```bash
# Create directory
mkdir -p data/raw/reef
cd data/raw/reef

# Download via curl (replace with the direct release URL from the repository)
curl -L -O https://github.com/REEF-Framework/REEF/releases/latest/download/reef_dataset.zip

# If downloaded as a ZIP archive, extract it:
unzip reef_dataset.zip
rm -f reef_dataset.zip
cd ../../..
```

##### Windows (PowerShell)
```powershell
New-Item -ItemType Directory -Force -Path data\raw\reef
Set-Location data\raw\reef
Invoke-WebRequest -Uri "https://github.com/REEF-Framework/REEF/releases/latest/download/reef_dataset.zip" -OutFile "reef_dataset.zip"
Expand-Archive -Path "reef_dataset.zip" -DestinationPath "."
Remove-Item "reef_dataset.zip"
Set-Location ..\..\..
```

---

### 2.2 CVEfixes (External Validation Dataset)

**Reference:** Bhandari et al., *"CVEfixes: A Comprehensive Dataset of Vulnerability Fixing Commits"*, Zenodo: [https://zenodo.org/records/13118970](https://zenodo.org/records/13118970).

CVEfixes is an independent dataset collected from open-source repositories and the National Vulnerability Database (NVD). It is provided primarily as an SQLite database dump (`cvefixes.db`) or zipped CSV tables.

#### Where to Find the Files
1. Visit Zenodo record [https://zenodo.org/records/13118970](https://zenodo.org/records/13118970).
2. Download the database archive `cvefixes.zip` or the SQLite database `cvefixes.db`.
3. Save the database file or extracted tables inside:
   ```
   vulnexplain/data/raw/cvefixes/
   ```

#### Download Commands

##### Linux / macOS / WSL2
```bash
mkdir -p data/raw/cvefixes
cd data/raw/cvefixes

# Download CVEfixes archive from Zenodo
curl -L -O https://zenodo.org/records/13118970/files/cvefixes.zip
unzip cvefixes.zip
rm -f cvefixes.zip
cd ../../..
```

##### Windows (PowerShell)
```powershell
New-Item -ItemType Directory -Force -Path data\raw\cvefixes
Set-Location data\raw\cvefixes
Invoke-WebRequest -Uri "https://zenodo.org/records/13118970/files/cvefixes.zip" -OutFile "cvefixes.zip"
Expand-Archive -Path "cvefixes.zip" -DestinationPath "."
Remove-Item "cvefixes.zip"
Set-Location ..\..\..
```

---

## 3. Storage Formats & Exact File Specifications

### Why Apache Parquet (`.parquet`) for Processed Data?
1. **Columnar Compression:** Parquet achieves 75–85% file size compression compared to plain CSV, saving gigabytes of disk space and memory.
2. **Schema Integrity:** Preserves exact data types (integers, strings, booleans) without parsing ambiguities like CSV delimiter collisions in source code.
3. **High-Speed I/O:** Loads into PyTorch `DataLoader` up to 10× faster than text files, keeping GPU utilization consistently high on modern GPUs like the NVIDIA RTX 4050.

### The Unified Schema
Every processed dataset generated by `prepare_data.py` uses the exact same 7 columns:

```
+-------------+--------+-------------------------------------------------------------+
| Column Name | Type   | Description & Formatting Rule                               |
+-------------+--------+-------------------------------------------------------------+
| id          | string | Unique identifier: e.g. "reef_a8f9c1" or "cvefixes_49102"   |
| code        | string | Full function source code (UTF-8, trimmed, > 15 chars)      |
| label       | int64  | Binary: 1 = Vulnerable (pre-fix), 0 = Patched (post-fix)    |
| language    | string | Normalized: 'c','cpp','csharp','go','java','javascript','python'|
| cwe         | string | Canonical CWE: e.g. 'CWE-78', 'CWE-89', 'UNKNOWN'          |
| project     | string | Repository/Project name (used for leakage-resistant split)  |
| commit_date | string | ISO Date string: 'YYYY-MM-DD'                               |
+-------------+--------+-------------------------------------------------------------+
```

---

## 4. Directory Structure Before and After Preprocessing

### Before Running `prepare_data.py` (Raw Downloaded State)
```
vulnexplain/data/raw/
├── reef/
│   └── reef_dataset.parquet   (or .csv / .jsonl)
└── cvefixes/
    └── cvefixes.db            (or extracted CSV tables)
```

### After Running `prepare_data.py` (Processed State)
```
vulnexplain/data/processed/
├── reef_functions.parquet        # Complete cleaned REEF function table
├── cvefixes_functions.parquet    # Complete cleaned CVEfixes external validation set
├── reef_train.parquet            # 80% train split (GroupShuffleSplit by project)
├── reef_val.parquet              # 10% validation split (unseen projects)
└── reef_test.parquet             # 10% in-distribution test split (unseen projects)
```

And model configuration files are generated automatically in:
```
vulnexplain/model/checkpoints/best/
├── cwe_map.json                  # Top 20 CWEs + "OTHER" tensor mapping
└── threshold.json                # Default / tuned decision threshold
```

---

## 5. Instant Dry-Run Option (No External Download Required)

If you want to verify the entire training and analysis pipeline right away on your local machine or RTX 4050 without waiting for gigabytes of dataset downloads:

```bash
# Generate 300 realistic synthetic multilingual samples and execute full preprocessing:
python model/prepare_data.py --sample 300 --generate-synthetic
```

This generates valid vulnerable and patched function pairs across all 7 supported languages, builds `data/processed/*.parquet`, maps the top CWEs, and outputs statistics to `results/data_stats.csv`.
