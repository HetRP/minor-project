# Prepare data before training

Run from the repository root:

```powershell
python -m preprocess
```

Dependencies: pandas, pyarrow, scikit-learn. No training, GPU, network requests,
or model downloads are performed. The old `python model/prepare_data.py` command
also calls this package.

## Inputs

Place function exports in `data/raw/cvefixes/` for training/validation and
`data/raw/reef/` for an independent test. CSV, Parquet and JSONL are supported.
Each row must contain `project` (or `repo`/`repository`), `language` (or `lang`),
and either:

- `func_before` and `func_after`: a verified vulnerable/fixed function pair;
- `code` (or `func_src`) and explicit `label` (or `target`): 1 vulnerable, 0 safe.

Optional fields: `cwe`/`cwe_id`/`cwes`, `commit_date`. Supported languages are C,
C++, C#, Go, Java, JavaScript and Python. Preserve repository identity across
all versions of a function. A function-pair export asserts that these functions
were actually affected by the security fix; this pipeline cannot verify that
assertion automatically.

NVD JSON files contain metadata and are counted, never used as code examples.
REEF commit records are staged as patched files and diffs in
`data/processed/reef_files_staged.jsonl`. They need verified reverse-patching,
function extraction and label review before they qualify as function exports.
The pipeline does not invent labels for arbitrary changed functions.

## Outputs

- `data/processed/*_functions_clean.csv` and `.parquet`: inspection tables,
  including when input data is incomplete. Empty tables mean no usable functions.
- When ready: `cvefixes_train`, `cvefixes_val`, `reef_test` in CSV and Parquet.
- `results/preprocessing_report.json`: readiness, blockers, malformed JSONL
  locations, rejected records, cleaning totals, conflicts, language/label
  counts, unknown CWE counts, length percentiles and suggested training weights.
- When ready: `results/data_stats.csv` and `model/checkpoints/cwe_map.json`.

Line endings are normalized; indentation, comments and identifiers are retained.
Empty/very short code, NUL characters and unsupported languages are removed.
Normalized identical code with conflicting labels is removed entirely; remaining
exact normalized duplicates are removed. Near-duplicate detection is not implemented.
Repositories are normalized and split deterministically 90/10 for development.
REEF repositories and normalized code overlapping development data are excluded.
Every final split must contain both classes. Validation and test distributions
are preserved; suggested class weights are calculated from training only.
The CWE vocabulary is also calculated from training only.

For an exact token-length audit with an already downloaded tokenizer:

```powershell
python -m preprocess --tokenizer-path path/to/local/tokenizer --max-length 512
```

Character counts alone do not estimate token counts reliably. Code is never
silently truncated or chunked: chunk-level vulnerability labels require knowing
where the vulnerable code occurs. The optional audit reports functions exceeding
the token budget so that this can be reviewed before training.

Exit status 0 means ready; 1 means required labeled data/splits are missing.
Check the report on every run; existing split files from earlier runs must not
be used when the latest report says incomplete. A ready report establishes the
schema and split checks, not dataset provenance or model accuracy.
