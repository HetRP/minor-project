# VulnExplain post-training integration and verification report

Training remains complete. The existing dual-head GraphCodeBERT checkpoint is integrated and tested on CUDA. Detection quality is poor, and generated LLM explanations/remediation could not be verified because no working provider is configured. No retraining, dataset downloads, threshold tuning, or checkpoint writes were performed in this integration task.

## Checkpoint and runtime

- Model: microsoft/graphcodebert-base; binary head plus 21 CWE classes; 512-token context.
- Device: NVIDIA GeForce RTX 4050 Laptop GPU; backend reports CUDA and uses FP16 autocast.
- Checkpoint: model/checkpoints/best; completed non-smoke training, best epoch 3.
- Classification threshold: 0.4734289348125458 (exact saved value, unchanged).
- All eight checkpoint artifacts have identical SHA-256 hashes before and after verification; strict state-dictionary loading succeeds. Local tokenizer and encoder config load without downloading the backbone.
- Saved model weight SHA-256: f095a3627e7c05619bdde57136271523062e390422bdee4436e7e99810c9f68d
- Maximum probability difference between backend and existing evaluation predictions on the six samples: 0.0000610352.

## Actual saved evaluation results

These are the completed benchmark results, not a new benchmark run. Prediction CSVs were independently reviewed to compute confusion counts.

| Dataset | Records | Accuracy | Precision | Recall | F1 | ROC-AUC | PR-AUC |
|---|---:|---:|---:|---:|---:|---:|---:|
| REEF held-out test | 1638 | 0.5104 | 0.5053 | 0.9915 | 0.6694 | 0.5241 | 0.5083 |
| CVEfixes external | 22873 | 0.3408 | 0.3336 | 0.9795 | 0.4978 | 0.5018 | 0.3322 |

| Dataset | TN | FP | FN | TP | Flagged | False-positive rate |
|---|---:|---:|---:|---:|---:|---:|
| reef_test | 24 | 795 | 7 | 812 | 98.11% | 97.07% |
| cvefixes_external | 325 | 14921 | 156 | 7471 | 97.90% | 97.87% |

| CWE head | Known vulnerable samples | Accuracy | Macro F1 | Weighted F1 |
|---|---:|---:|---:|---:|
| reef_test | 807 | 0.3532 | 0.1165 | 0.3019 |
| cvefixes_external | 6509 | 0.4176 | 0.1240 | 0.3453 |

CWE scores evaluate the CWE head on known-label vulnerable samples, with rare/unseen categories mapped to OTHER. They do not measure successful end-to-end detection plus categorization. Near-chance ROC-AUC and the extremely high false-positive rate are the primary blockers. F1 is misleading without the precision/recall tradeoff. A displayed probability is a model score, not a calibrated guarantee of correctness.

## Integration changes

- Detector loads the saved tokenizer and local encoder config, then strictly loads the real dual-head weights; training constructor defaults and architecture remain intact.
- Present but incomplete/corrupt checkpoints and inference errors now fail explicitly rather than silently substituting heuristics. Heuristics remain available only when no trained weights exist, with an explicit prediction_source.
- Backend inference uses the same bounded tokenization and FP16/float32 probability calculation as evaluation. Scores retain precision until frontend formatting; binary decisions use the exact threshold.
- Findings persist language and prediction_source through an additive SQLite migration. This fixes language filtering and non-Python remediation validation for new findings. Legacy findings are not backfilled.
- Corrected UTF-8 byte slicing in AST extraction and an empty-sink chat crash.
- Removed invented sink/entry-point assertions when localization/caller resolution provides no evidence, and corrected the concrete platform.system() false positive. Static sink rules remain approximate.
- Offline remediation preserves the original function and reports that no executable patch was generated. It no longer replaces code with generic comments. Validation never fabricates a reduced probability if inference is missing.
- Offline summaries/block text explicitly state analysis is unavailable instead of asserting an unverified exploit. Frontend displays unavailable-patch messages and only displays validation verdicts when populated. Existing six-view UI and API architecture remain.
- Installed existing frontend dependencies, optional browser/http test dependencies, Chromium, and the missing MiniLM embedding model. No REEF/CVEfixes data was downloaded.

## Nine-stage verification

| Stage | Actual test and outcome |
|---|---|
| 1 Ingestion | Local directory ingestion: six full real dataset functions, six files. Remote Git cloning was not tested. |
| 2 AST/program analysis | All seven language parser smoke checks passed; Unicode source extraction regression passed. Real scan built call/def-use data. |
| 3 Neural detection | Real checkpoint on CUDA; direct-forward probability/CWE comparison and saved-evaluation comparison passed. Forced inference errors propagate. |
| 4 Localization | Real scan persisted localization results; platform.system is excluded and os.system is recognized by regression tests. Sink patterns do not prove exploitability. |
| 5 Flowcharts | All six real-function diagrams rendered to SVG in Chromium; unresolved callers/sinks are labeled unknown rather than fabricated. |
| 6 Explanations | Summary/block API and progressive UI tested. Offline availability text displayed. Source-specific generated LLM explanations are UNVERIFIED. |
| 7 Remediation | Fix API exercised. No provider returned a patch; original code and empty diff preserved; UI shows unavailable status. Successful generated remediation is UNVERIFIED. |
| 8 Validation | Real patched dataset functions syntax-checked and rescored through the neural model; all three checks passed. They remain flagged by this weak detector. Unavailable generated fix correctly yields unchanged code/verdict. |
| 9 Repository RAG/chat | Actual MiniLM embeddings and persisted FAISS index built; retrieval and citation/intent API plus browser display passed. Natural-language response quality is UNVERIFIED because replies use offline fallback. |

The stages are exercised through scan, finding, explain, fix and chat endpoints; fixes/validation/chat are on-demand operations, not automatic security proof during a scan.

## Unseen-repository samples

Six real REEF test functions from three repositories absent from REEF training. Three vulnerable and three patched functions were chosen deterministically, without selecting favorable model outputs. These are previously held-out benchmark samples, not newly collected repositories or a new independent benchmark. Original functions were never executed. Same-name revisions are tested; this verification does not independently audit their CVE labels.

| Repository | Dataset label | Probability | Predicted CWE | Flagged |
|---|---|---:|---|---|
| github.com/apache/airflow | vulnerable | 0.512113 | OTHER | True |
| github.com/apache/airflow | patched | 0.510222 | OTHER | True |
| github.com/bbengfort/confire | vulnerable | 0.552781 | OTHER | True |
| github.com/bbengfort/confire | patched | 0.550638 | OTHER | True |
| github.com/cloudfoundry/php-buildpack | vulnerable | 0.508567 | OTHER | True |
| github.com/cloudfoundry/php-buildpack | patched | 0.508567 | OTHER | True |

All six were flagged, including all three patched functions; all six predicted OTHER. One vulnerable/patched pair has identical probability under 512-token truncation. This is a demonstrated quality failure, despite functioning integration.

## Test evidence and artifacts

- Pytest: 15 passed; three Tree-sitter deprecation warnings. Includes model/data regressions, all seven parsers, checkpoint fallback guards, offline patch preservation and sink localization.
- Backend integration: all 11 recorded checks passed; scan scan_acbc08e48ad5.
- Chromium 156.0.8078.4: all 9 UI acceptance checks passed; zero page errors, console errors or failed requests in the final unrestricted run. Earlier sandbox-only external font loading failed; final run confirms this was an environment restriction.
- Production frontend build passed (Vite 5.4.21); existing large Mermaid chunk warnings remain. Browser acceptance used Vite development serving, not a deployment.
- Machine-readable evidence: integration/backend_verification.json, browser_verification.json, evaluation_review.json.
- Screenshots: integration/dashboard.png and integration/finding.png.
- Full benchmark details: metrics_overall.json; prediction CSVs; actual_training_report.md.
- All verification scans and RAG indexes use isolated results/integration SQLite/files, separate from normal scan history. Importing db initializes/migrates the normal schema as designed; existing records are preserved.

## Remaining issues and limits

1. Model quality needs training-data/label audits, input-truncation diagnostics and objective tuning before reliable use. Integration did not change weights or select a new threshold.
2. No working Groq/HuggingFace LLM provider is configured. Generated explanations, usable fixes and grounded answer quality cannot be claimed. Configure a provider locally without putting secrets in reports, then rerun those tests.
3. Current flowcharts are a coarse deterministic def-use/sink view, not a complete statement/branch/callee execution graph as described in the guide. Full semantic flow accuracy has not been proven.
4. Localization is regex-based and has no full taint analysis; sink presence and assigned CWE/severity are hypotheses.
5. Existing GraphCodeBERT architecture uses source tokens/CLS, not explicit GraphCodeBERT DFG attention; preserved as requested.
6. Code Explorer file contents are in-memory and unavailable for older scans after backend restart. Persistent history still holds findings. Concurrency/load, large repositories, remote cloning and deployment were not tested.
7. Suggested patches are not executed against upstream tests. Syntax and probability changes do not establish functional correctness or security.

## Reproduce verification

From the existing workspace root with its .venv:

```powershell
.venv/Scripts/python.exe -m pytest vulnexplain/backend/tests/test_smoke.py vulnexplain/backend/tests/test_integration_guards.py vulnexplain/model/tests/test_real_data.py -q
.venv/Scripts/python.exe vulnexplain/backend/tests/verify_integration.py
```

For browser checks, run backend/tests/serve_verification.py (isolated API on 127.0.0.1:8765), start the existing frontend with VITE_API_URL=http://127.0.0.1:8765 on port 5175, then run backend/tests/verify_browser.py. Install requirements-verification.txt and Chromium only if needed. The browser check expects the current unavailable-provider state; adapt expectations after configuring a provider. Standard application serving remains unchanged.
