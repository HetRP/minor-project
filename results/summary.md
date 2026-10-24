# VulnExplain Evaluation Summary

## Overall Performance Table
| Benchmark Dataset | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REEF Test (In-Dist)** | 0.5104 | 0.5053 | 0.9915 | **0.6694** | 0.0762 | 0.5241 | 0.5083 |
| **CVEfixes (External)** | 0.3408 | 0.3336 | 0.9795 | **0.4978** | 0.0028 | 0.5018 | 0.3322 |

*Tuned Decision Threshold:* `0.47`

## Breakdown by Programming Language (REEF Test)
| language   |   samples |   accuracy |   precision |   recall |     f1 |    mcc |
|:-----------|----------:|-----------:|------------:|---------:|-------:|-------:|
| c          |       244 |     0.5164 |      0.5085 |   0.9836 | 0.6704 | 0.0921 |
| cpp        |        88 |     0.5    |      0.5    |   0.9773 | 0.6615 | 0      |
| csharp     |        22 |     0.5    |      0.5    |   0.8182 | 0.6207 | 0      |
| go         |       206 |     0.5049 |      0.5024 |   1      | 0.6688 | 0.0698 |
| java       |       384 |     0.5052 |      0.5026 |   0.9948 | 0.6678 | 0.0513 |
| javascript |        82 |     0.5    |      0.5    |   1      | 0.6667 | 0      |
| python     |       612 |     0.5163 |      0.5083 |   0.9967 | 0.6733 | 0.1179 |

## Analysis of Generalization Gap
- REEF Test is project-disjoint (GroupShuffleSplit on projects), measuring generalization to unseen codebases within the same distribution.
- CVEfixes evaluates cross-dataset generalization under distribution shift (differing vulnerability discovery mechanisms and commit practices).
- MCC and PR-AUC serve as primary indicators under class imbalance.
