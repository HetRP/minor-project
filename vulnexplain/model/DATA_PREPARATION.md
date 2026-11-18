# Data preparation

Run `python model/prepare_data.py` from the project root.

CVEfixes supplies training and validation, split by repository (90/10 of repositories,
not necessarily rows). REEF supplies external testing only. Training inputs are
`data/processed/cvefixes_train.parquet` and `cvefixes_val.parquet`; external evaluation
reads `reef_test.parquet`. Tokenization happens in the training data loader.

## Current supplied files

The CVEfixes directory has 23 NVD metadata feeds, not labeled function code.
REEF has commit records containing patched files and unified diffs. Preparation
cleans those records into `data/processed/reef_files_staged.jsonl`, preserving
provenance, CVE/CWE metadata, patched code and patches. It excludes descriptions
and LLM explanations from inputs. This staging artifact is not a labeled test set.
See `results/preprocessing_report.json` for counts and blockers. Exit code 1 means
preparation remains incomplete; no synthetic examples are substituted.

## Required function exports

Place CSV, Parquet or JSONL function exports under the respective `data/raw/cvefixes`
and `data/raw/reef` directories. Required fields:

- `func_before` and `func_after` (vulnerable/fixed source), OR `code` and binary `label`.
- `language`: C, C++, C#, Go, Java, JavaScript or Python.
- `project`: repository identity, preferably owner/repository or a GitHub URL.
- `cwe`: canonical CWE identifier; missing values become UNKNOWN.
- Optional `commit_date`: a parseable date; missing dates remain empty.

Use consistent repository identities in both datasets. Export actual functions,
not NVD descriptions or whole files. Native CVEfixes SQLite is not yet accepted:
export its method-level code and join repository, language and vulnerability metadata
into the schema above first. For REEF, verify reverse application of each diff against
patched code, then use AST extraction to locate changed pre/post functions. Review
security relevance; unrelated functions touched by a security commit are not proven
vulnerable. Function labels derived from fixes remain noisy ground truth.

Preparation normalizes line endings while preserving indentation and code content,
rejects empty/short/unsupported entries, removes conflicting-label code and normalized
duplicates, and excludes test repository/code overlap with CVEfixes development data.
CWE categories are learned from training only. It never overwrites an existing best
checkpoint CWE map. Approximate clones and shared CVEs across different repositories
are not currently detected.

Once the report says ready, run `python model/train.py`, then
`python model/evaluate.py`. Threshold tuning uses CVEfixes validation only. Evaluation
requires trained weights and never reports fabricated benchmark predictions.
