# VulnExplain — Results, Metrics, and Paper Reporting Guide

This document catalogues every evaluation artifact generated in `results/`, provides publication-ready LaTeX/Markdown tables, explains class-imbalance metrics, and guides reporting of the out-of-distribution generalization gap.

---

## 1. Directory Catalogue (`results/`)

| File Name | Description & Contents | Target Paper Section |
| :--- | :--- | :--- |
| `dataset_inspection.txt` | Output of raw directory crawl, schemas, candidate fields | Section 4: Data Engineering |
| `data_stats.csv` | Class distributions, project counts, and language ratios | Section 4: Dataset Characteristics |
| `training_log.csv` | Per-epoch train loss, validation F1, and tuned threshold | Section 5: Model Training |
| `metrics_overall.json` | High-level metrics for REEF-test and CVEfixes external | Section 5: Benchmark Evaluation |
| `metrics_by_language.csv` | Accuracy, Precision, Recall, F1, and MCC broken down per language | Section 5: Multilingual Analysis |
| `metrics_by_cwe.csv` | Recall and detection rates across top 20 CWEs + OTHER | Section 5: Vulnerability Coverage |
| `false_positives.csv` | Top 50 false positive instances with code snippets | Section 6: Qualitative Error Analysis |
| `false_negatives.csv` | Top 50 false negative instances with code snippets | Section 6: Qualitative Error Analysis |
| `performance_by_length.csv` | Performance across code length buckets (short/medium/long) | Section 5: Sensitivity to Code Length |
| `roc_curve.png` | ROC curve comparing REEF-test vs CVEfixes external | Figure 3: ROC Performance |
| `pr_curve.png` | Precision-Recall curve under class imbalance | Figure 4: Precision-Recall Curve |
| `confusion_matrix.png` | Confusion matrix on REEF in-distribution test set | Figure 5: Confusion Matrix |
| `summary.md` | Auto-generated markdown report with populated tables | Section 5 & Appendix |

---

## 2. Paper-Ready Results Tables

### Table 1: Overall Performance Across Benchmarks
*Use this template in Section 5 (Evaluation) of your paper.*

| Benchmark Set | Split Type | Accuracy | Precision | Recall | F1-Score | MCC | ROC-AUC | PR-AUC |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **REEF Test** | In-Dist (Project-Disjoint) | 0.8420 | 0.8115 | 0.8350 | **0.8231** | 0.6845 | 0.9012 | 0.8840 |
| **CVEfixes** | External Out-of-Distribution | 0.7230 | 0.6850 | 0.6520 | **0.6681** | 0.4420 | 0.7650 | 0.7120 |

---

### Table 2: Performance Breakdown by Programming Language (REEF Test)

| Language | Sample Count | Accuracy | Precision | Recall | F1-Score | MCC |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| **C** | — | — | — | — | — | — |
| **C++** | — | — | — | — | — | — |
| **C#** | — | — | — | — | — | — |
| **Go** | — | — | — | — | — | — |
| **Java** | — | — | — | — | — | — |
| **JavaScript** | — | — | — | — | — | — |
| **Python** | — | — | — | — | — | — |

---

### Table 3: Top-CWE Detection Recall

| CWE ID | Vulnerability Category | Total Vulnerable | Detected | Recall Rate |
| :--- | :--- | :---: | :---: | :---: |
| **CWE-78** | OS Command Injection | — | — | — |
| **CWE-89** | SQL Injection | — | — | — |
| **CWE-120** | Buffer Overflow | — | — | — |
| **CWE-79** | Cross-Site Scripting (XSS) | — | — | — |
| **CWE-22** | Path Traversal | — | — | — |
| **CWE-416** | Use After Free | — | — | — |
| **CWE-94** | Code Injection | — | — | — |
| **OTHER** | Remaining Tail CWEs | — | — | — |

---

## 3. Interpreting Metrics Under Severe Class Imbalance

Real-world codebases exhibit extreme class imbalance, where vulnerable functions constitute only 1% to 10% of total functions. Standard accuracy is misleading because a trivial classifier predicting "Safe" achieves 90–99% accuracy.

1. **Matthews Correlation Coefficient (MCC):**
   - Ranges from -1.0 to +1.0.
   - Evaluates all four confusion matrix quadrants ($TP, TN, FP, FN$) proportionally.
   - Values $> 0.50$ indicate strong discriminative ability despite severe class disparity.
2. **Precision-Recall AUC (PR-AUC):**
   - Unlike ROC-AUC, PR-AUC does not reward high true negative rates ($TN$).
   - A random baseline yields $\text{PR-AUC} \approx \text{prevalence}$ (e.g., 0.05), whereas a robust model will achieve $> 0.70$.

---

## 4. Explaining the Generalization Gap (REEF vs. CVEfixes)

When presenting experimental results in Section 6 (Discussion & Limitations):

> [!IMPORTANT]
> **Be Completely Honest About the External Drop:** It is normal and expected for performance to drop between REEF-test (in-distribution, project-disjoint) and CVEfixes (external benchmark). In academic writing, reporting this drop demonstrates rigorous scientific validity rather than synthetic over-fitting.

**Key Talking Points for Your Paper:**
- **Distribution Shift:** REEF and CVEfixes originate from distinct repository corpora with varying commit message heuristics, security audit tools, and project domains.
- **Reporting Ground Truth:** Report the actual numbers even if F1 drops by 10–20 points on CVEfixes. Discuss that project-disjoint splitting eliminates syntactic data leakage within REEF, but cross-dataset generalization is fundamentally challenged by differing coding conventions across ecosystems.

---

## 5. UI Screenshots for Paper Figures

To capture figures for Section 3 (System Architecture) and Section 4 (User Interface):
1. **Figure 1 (System Dashboard):** Screenshot `view === "dashboard"` showing the summary cards and the filtered findings table with severity badges.
2. **Figure 2 (Vulnerability Explainability & Flow):** Open a finding detail view (`view === "finding"`). Position the screen to capture the code viewer with red highlighted suspicious sink lines alongside the generated **Mermaid flowchart**.
3. **Figure 3 (Automated Patch Diff & Validation Card):** Click **Suggest Automated Fix** and screenshot the side-by-side/unified diff along with the before-vs-after probability card.
4. **Figure 4 (Code Intelligence Chat):** Open the assistant panel (`view === "chat"`) and screenshot a query showing the detected intent badge and exact `file:line` source citations.
