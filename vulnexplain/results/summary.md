# VulnExplain Evaluation Summary

## Overall Performance Table
| Benchmark Dataset | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | PR-AUC |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **REEF External Test** | 0.5802 | 0.5458 | 0.9386 | **0.6902** | 0.2324 | 0.6649 | 0.6572 |

*Tuned Decision Threshold:* `0.15`

## Breakdown by Programming Language (REEF Test)
| language   |   samples |   accuracy |   precision |   recall |     f1 |    mcc |
|:-----------|----------:|-----------:|------------:|---------:|-------:|-------:|
| c          |      1034 |     0.5377 |      0.52   |   0.9574 | 0.6739 | 0.141  |
| cpp        |       370 |     0.5622 |      0.535  |   0.913  | 0.6747 | 0.1787 |
| csharp     |        48 |     0.5208 |      0.5106 |   1      | 0.6761 | 0.1459 |
| go         |       368 |     0.5435 |      0.5235 |   0.9674 | 0.6794 | 0.164  |
| java       |      1345 |     0.6535 |      0.601  |   0.8997 | 0.7206 | 0.3553 |
| javascript |       805 |     0.5404 |      0.5214 |   0.9701 | 0.6783 | 0.1595 |
| python     |       244 |     0.582  |      0.5472 |   0.9508 | 0.6946 | 0.2428 |

## Analysis of Generalization Gap
- Training and threshold selection use CVEfixes training and validation only.
- REEF measures external generalization; preprocessing excludes repositories and normalized code shared with CVEfixes development data.
- MCC and PR-AUC serve as primary indicators under class imbalance.
