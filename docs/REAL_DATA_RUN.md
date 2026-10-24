# Real-data training in the existing project

Run from `vulnexplain`, using the existing parent `.venv`:

```powershell
& '..\.venv\Scripts\python.exe' model/run_real_training.py
```

This runs real preparation, a separate 64-row CUDA smoke test, three full epochs,
and evaluation. It stops on any failure. No dataset is downloaded and no synthetic
records or mock predictions are produced. The frontend/backend are unchanged.

Training uses GraphCodeBERT and the existing two heads, 512 tokens, batch 8,
accumulation 2, FP16, gradient checkpointing, learning rate 2e-5, seed 42.
Batch 8 was verified on the actual RTX 4050 with a 2,422 MiB PyTorch memory peak.
Model selection and threshold tuning use REEF validation only. CVEfixes is used
only in the final external evaluation. REEF repository groups target 80/10/10;
row fractions differ with repository size. Exact code hashes are disjoint.
CVEfixes repositories/code overlapping any REEF split are excluded.

REEF contains nested fixing-commit/file records, not ready-to-train functions.
The new-side unified diff must match `raw_code`; reversal reconstructs pre-fix
files. Only changed, uniquely named, AST-valid functions with both versions are
retained. Malformed/truncated patches and timed-out parses are counted/excluded.
These are CVE-fix weak labels; a changed function is not an independently audited
vulnerability, and a post-fix function is not guaranteed globally safe.
Missing REEF commit dates remain empty, rather than fabricated.
For the existing single-label CWE head, multiple CWEs resolve deterministically
to the lowest numeric CWE. The training-only top 20 map plus OTHER is preserved.

CVEfixes' local compressed SQLite dump is streamed into a derived compact SQLite
cache in `data/processed`. Raw files stay untouched. Only needed columns are
retained. A completion marker prevents accidental reuse of interrupted imports.
Function labels come from verified True/False values of `before_change`; joins
connect method_change → file_change → commits → fixes → cwe_classification.
External deduplication uses an on-disk SQLite manifest. Full function bodies are
written in byte-bounded Parquet row groups and streamed during evaluation. No
eligible record is discarded merely to fit RAM. Tokenization expands a source
prefix until the selected 512 tokens agree with a doubled prefix, avoiding
whole-body tokenization of enormous generated functions. Full code remains in
the seven-column Parquet output. Dataset fingerprints are computed in chunks.
Interrupted SQL restoration can resume with:
`python model/prepare_data.py --restore-only --resume-import`.

Outputs:
- `results/dataset_inspection.txt`, `cvefixes_schema.json`, `reef_provenance.jsonl`
- `results/data_validation.json`, `data_stats.csv`
- `results/pipeline_status.json` (completed only after evaluation exits zero)
- `results/{prepare,smoke,train,evaluate}_console.log`
- `results/training_log.csv`, `metrics_overall.json`, plots and prediction CSVs
- `model/checkpoints/smoke/` (never used as the production checkpoint)
- `model/checkpoints/best/`: weights, tokenizer, config, CWE map, threshold,
  training configuration/duration/status, data hashes and validation manifest

Existing best weights are backed up before a new training run. Preparation does
not rewrite the existing best checkpoint's CWE map. Evaluation requires a
completed non-smoke training manifest and matching dataset hashes; missing
weights are an error. CWE classification metrics use truly vulnerable samples
with known labels; unseen known CWEs map to OTHER, UNKNOWN labels are excluded.
