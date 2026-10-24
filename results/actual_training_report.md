# Actual VulnExplain training and evaluation report

All three epochs and both evaluations completed. No datasets were downloaded. The existing frontend, backend, and dual-head GraphCodeBERT architecture were preserved.

**Result quality:** binary discrimination remains close to chance. Completion of training does not establish a reliable vulnerability detector.

## Prepared real datasets

REEF: 4,466 raw commit records examined; 14,989 cleaned function records retained. CVEfixes: 218,420 supported-language method records examined; 22,873 retained for external evaluation.

| Dataset | Rows | Vulnerable (1) | Patched (0) | Repositories |
|---|---:|---:|---:|---:|
| reef_train | 12411 | 6208 | 6203 | 988 |
| reef_val | 940 | 469 | 471 | 123 |
| reef_test | 1638 | 819 | 819 | 124 |
| cvefixes_functions | 22873 | 7627 | 15246 | 1255 |

All four files have the specified seven columns, int64 labels, both classes, and all seven languages. Repository groups target 80/10/10; sample fractions differ with repository size. All six pairs have zero repository and normalized full-code hash overlap. CVEfixes was excluded from training, model selection, and threshold tuning.

## Training configuration and measured duration

- GPU: NVIDIA GeForce RTX 4050 Laptop GPU (6 GiB). CUDA build: 2.6.0+cu124.
- Model: microsoft/graphcodebert-base; existing binary head and 21-class CWE head.
- Epochs: 3; encoder learning rate: 2e-05; head learning rate: 5e-5.
- Batch: 8; accumulation: 2; effective batch: 16; tokens: 512.
- FP16 mixed precision and encoder gradient checkpointing enabled.
- Trainer measured duration: 1391.625 seconds (23.19 minutes).
- Peak PyTorch GPU allocation: 2425.72 MiB.
- Selected epoch: 3; validation-selected threshold: 0.473428935.

## Epoch results

Loss is the combined weighted binary loss plus 0.3 times vulnerable-sample CWE loss.

| Epoch | Combined loss | Val accuracy | Val precision | Val recall | Val F1 | Val ROC-AUC | Val PR-AUC | Seconds |
|---|---:|---:|---:|---:|---:|---:|---:|---:|
| 1 | 1.4169 | 0.5053 | 0.5021 | 1.0000 | 0.6686 | 0.5077 | 0.5084 | 451.01 |
| 2 | 1.2220 | 0.5043 | 0.5016 | 1.0000 | 0.6681 | 0.5161 | 0.5134 | 448.0 |
| 3 | 1.1118 | 0.5074 | 0.5032 | 0.9957 | 0.6686 | 0.5201 | 0.5206 | 445.2 |

## Frozen-checkpoint binary evaluation

| Dataset | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC | MCC |
|---|---:|---:|---:|---:|---:|---:|---:|
| reef_test | 0.5104 | 0.5053 | 0.9915 | 0.6694 | 0.5241 | 0.5083 | 0.0762 |
| cvefixes_external | 0.3408 | 0.3336 | 0.9795 | 0.4978 | 0.5018 | 0.3322 | 0.0028 |

## CWE classification

Computed on truly vulnerable samples with known CWE labels. Unseen known categories map to OTHER; UNKNOWN labels are excluded. These are separate CWE-head metrics, not end-to-end correct vulnerability-and-CWE detection rates.

| Dataset | Samples | Accuracy | Macro F1 | Weighted F1 |
|---|---:|---:|---:|---:|
| reef_test | 807 | 0.3532 | 0.1165 | 0.3019 |
| cvefixes_external | 6509 | 0.4176 | 0.1240 | 0.3453 |

## Measured limitations

- Validation and both benchmarks show weak binary discrimination and excessive positive predictions. High recall/F1 should not be interpreted as strong security detection.
- Training context audit: 1998 of 12,411 training records have opposite labels sharing identical 512-token inputs. The corresponding validation count is 129 of 940. Full-source conflicts were removed; truncation still loses distinguishing information. This contributes ambiguity but does not by itself explain all weak performance.
- CVE-fix changed-function labels are weak supervision, not independent proof that every changed function was vulnerable or every patched function is globally safe.
- Missing REEF commit dates were retained as empty strings rather than fabricated.
- Multiple CWEs resolve deterministically to the lowest numeric category because the preserved CWE head is single-label.

## Saved artifacts

- Checkpoint directory: `C:\Users\Het Patel\Desktop\Minor_Project\minor-main\vulnexplain\model\checkpoints\best`
- Weights: `model/checkpoints/best/pytorch_model.bin` (501,065,094 bytes).
- Tokenizer, encoder config, CWE map, threshold, data validation snapshot, package versions and training status are saved alongside the weights.
- Training: `results/training_log.csv`, `results/train_console.log`.
- Evaluation: `results/metrics_overall.json` (including per-class CWE reports), prediction CSVs, per-language/per-CWE CSVs, false positives/negatives and length analysis.
- Plots: `results/roc_curve.png`, `results/pr_curve.png`, `results/confusion_matrix.png`.
- Data checks: `results/data_validation.json`, `results/artifact_validation.json`, `results/dataset_inspection.txt`, `results/reef_provenance.jsonl`, `results/cvefixes_schema.json`.
- Verification: six regression checks passed; streamed/in-memory prediction equivalence passed on eight real validation records with zero probability difference.
- Run instructions: `docs/REAL_DATA_RUN.md`.
