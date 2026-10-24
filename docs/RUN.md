# VulnExplain — Complete Execution and Run Guide

Follow these numbered steps to run the complete VulnExplain platform from scratch.

---

## 1. Prerequisites
- Python 3.10, 3.11, or 3.12
- Node.js 18+ and npm
- Git

---

## 2. Step-by-Step Setup

### Step 0: Clone and Navigate to Directory
```bash
cd vulnexplain
```

### Step 1: Create and Activate Python Virtual Environment
#### Linux / macOS
```bash
python3 -m venv venv
source venv/bin/activate
```

#### Windows (PowerShell)
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

### Step 2: Install Python Dependencies
```bash
pip install --upgrade pip
pip install -r requirements.txt
```

### Step 3: Configure Environment Variables
Copy the template `.env.example` to `.env`:
```bash
cp .env.example .env
```
Open `.env` and configure your free API keys:
1. **Groq API Key (Free):**
   - Visit [https://console.groq.com/keys](https://console.groq.com/keys), sign up, and create a free API key.
   - Set `GROQ_API_KEY=gsk_your_key_here`.
   - Set `GROQ_MODEL=llama-3.3-70b-versatile` (or `llama-3.1-8b-instant`).
2. **HuggingFace Inference API Token (Free Fallback):**
   - Visit [https://huggingface.co/settings/tokens](https://huggingface.co/settings/tokens) and generate a free Read token.
   - Set `HF_TOKEN=hf_your_token_here`.

> [!NOTE]
> Even without any API keys, VulnExplain includes an offline deterministic template fallback engine so the backend and UI will never crash.

### Step 4: Run Training on NVIDIA RTX 4050 (or Use Pre-configured Mode)

If you have an **NVIDIA GeForce RTX 4050 (6GB VRAM)**, you can run the entire model preparation, fine-tuning, and evaluation pipeline at once with optimal batch and accumulation parameters:

#### Option A: One-Click Runner Script
- **Windows (PowerShell / Command Prompt):**
  ```cmd
  scripts\run_pipeline_rtx4050.bat
  ```
- **Linux / macOS / WSL2:**
  ```bash
  bash scripts/run_pipeline_rtx4050.sh
  ```

#### Option B: Manual Step-by-Step Commands
```bash
# 1. Prepare Parquet data (GroupShuffleSplit by project)
python model/prepare_data.py

# 2. Train GraphCodeBERT on RTX 4050 (Batch=8, GradAccum=2 -> Effective=16, FP16)
python model/train.py --batch_size 8 --grad_accum 2 --epochs 3 --max_len 512

# 3. Evaluate checkpoint on REEF test and CVEfixes external benchmarks
python model/evaluate.py
```

> [!NOTE]
> If you wish to test the web UI and analysis pipeline immediately without training, the repository already includes default configuration maps (`threshold.json` and `cwe_map.json`) and runs in AST heuristic detection mode so you can start right away.

### Step 5: Start Backend API Server
From the `vulnexplain/` root directory:
```bash
# Using uvicorn directly:
uvicorn backend.main:app --host 0.0.0.0 --port 8000 --reload

# Or via Python module:
python backend/main.py
```
Verify the backend is healthy by visiting [http://localhost:8000/api/health](http://localhost:8000/api/health) in your browser. You should see:
```json
{
  "status": "healthy",
  "detector_loaded": false,
  "device": "cpu",
  "groq_configured": true
}
```

### Step 6: Start Frontend Development Server
In a separate terminal window:
```bash
cd frontend
npm install
npm run dev
```
Open your browser to [http://localhost:5173](http://localhost:5173).

---

## 3. Running a Verification Scan

1. In the web interface at `http://localhost:5173`, enter a small public repository URL in the search bar.
   - Example 1: `https://github.com/octocat/Hello-World`
   - Example 2: Any small public Python/C/JS repository.
2. Click **Scan Repo**.
3. Observe the live progress bar transition through the 9 pipeline stages:
   - *Ingestion → AST Parsing → GraphCodeBERT Detection → Localization → Flow Generation → Initial Explanation → RAG Indexing*.
4. On completion, explore:
   - **Dashboard:** Filter findings by severity and language.
   - **Finding Detail:** Inspect highlighted sink lines, click **Next Part** for progressive block explanations, and view the Mermaid flowchart.
   - **Automated Fix:** Click **Suggest Automated Fix** to generate a unified diff and probabilistic validation card.
   - **Code Explorer:** Navigate repository files and see which files contain vulnerabilities.
   - **Assistant:** Ask questions such as *"How do I fix the vulnerability in line X?"* or *"What is the architecture of this repo?"*

---

## 4. Running Automated Tests

Run the automated smoke test suite using `pytest`:
```bash
pytest backend/tests/test_smoke.py -v
```

This validates:
- Multilingual AST parsing across all 7 supported languages (C, C++, C#, Go, Java, JS, Python)
- Detector bounded scoring
- Mermaid flowchart generation
- 5-category intent classification for the chat assistant

---

## 5. Troubleshooting

| Symptom | Cause | Solution |
| :--- | :--- | :--- |
| `ModuleNotFoundError: No module named 'tree_sitter'` | Missing dependencies | Run `pip install -r requirements.txt` within active virtualenv. |
| Backend port 8000 already in use | Another service is using port 8000 | Specify a different port: `uvicorn backend.main:app --port 8080` and update `VITE_API_URL=http://localhost:8080` in `.env`. |
| Git clone failure: `Authentication failed` | Private repository URL | Ensure you only provide public repository URLs. |
| Chat says "Offline Remediation Template" | Groq key not set | Verify `GROQ_API_KEY` in `.env` and restart backend. |
