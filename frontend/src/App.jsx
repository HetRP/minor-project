import React, { useState, useEffect, useRef } from "react";
import mermaid from "mermaid";

const API_BASE = import.meta.env.VITE_API_URL || "http://localhost:8000";

mermaid.initialize({
  startOnLoad: false,
  theme: "neutral",
  securityLevel: "loose",
});

export default function App() {
  const [view, setView] = useState("home"); // home | progress | dashboard | finding | explorer | chat
  const [repoUrl, setRepoUrl] = useState("");
  const [activeScanId, setActiveScanId] = useState(null);
  const [scanData, setScanData] = useState(null);
  const [recentScans, setRecentScans] = useState([]);
  const [findings, setFindings] = useState([]);
  const [selectedFinding, setSelectedFinding] = useState(null);
  const [activeBlockIndex, setActiveBlockIndex] = useState(0);
  const [loadingBlock, setLoadingBlock] = useState(false);
  const [fixLoading, setFixLoading] = useState(false);
  const [filesData, setFilesData] = useState([]);
  const [selectedFile, setSelectedFile] = useState(null);
  
  // Filters
  const [filterSeverity, setFilterSeverity] = useState("ALL");
  const [filterLang, setFilterLang] = useState("ALL");

  // Chat
  const [chatMessages, setChatMessages] = useState([
    {
      sender: "assistant",
      text: "Hello! I am your repository code intelligence assistant. Ask me about vulnerabilities, data flows, remediations, or architecture.",
      intent: "greeting",
      sources: [],
    },
  ]);
  const [chatInput, setChatInput] = useState("");
  const [chatLoading, setChatLoading] = useState(false);

  // Mermaid container ref
  const mermaidRef = useRef(null);

  // Fetch recent scans on mount
  useEffect(() => {
    fetchRecentScans();
  }, []);

  const fetchRecentScans = async () => {
    try {
      const res = await fetch(`${API_BASE}/api/scans`);
      if (res.ok) {
        const data = await res.json();
        setRecentScans(data);
      }
    } catch (e) {
      console.error("Failed to load recent scans:", e);
    }
  };

  // Start new scan
  const handleStartScan = async (e) => {
    if (e) e.preventDefault();
    if (!repoUrl.trim()) return;

    try {
      const res = await fetch(`${API_BASE}/api/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ repo_url: repoUrl.trim() }),
      });
      if (res.ok) {
        const data = await res.json();
        setActiveScanId(data.scan_id);
        setView("progress");
      }
    } catch (err) {
      alert("Error initiating scan: " + err.message);
    }
  };

  // Poll scan progress
  useEffect(() => {
    let timer;
    if (view === "progress" && activeScanId) {
      const poll = async () => {
        try {
          const res = await fetch(`${API_BASE}/api/scan/${activeScanId}`);
          if (res.ok) {
            const data = await res.json();
            setScanData(data);
            if (data.status === "done") {
              await loadScanResults(activeScanId);
              setView("dashboard");
            } else if (data.status === "failed") {
              // stop polling
            } else {
              timer = setTimeout(poll, 1500);
            }
          }
        } catch (err) {
          timer = setTimeout(poll, 2500);
        }
      };
      poll();
    }
    return () => clearTimeout(timer);
  }, [view, activeScanId]);

  // Load results for a completed scan
  const loadScanResults = async (id) => {
    try {
      const [scanRes, findingsRes, filesRes] = await Promise.all([
        fetch(`${API_BASE}/api/scan/${id}`),
        fetch(`${API_BASE}/api/scan/${id}/findings`),
        fetch(`${API_BASE}/api/scan/${id}/files`),
      ]);
      if (scanRes.ok) setScanData(await scanRes.json());
      if (findingsRes.ok) setFindings(await findingsRes.json());
      if (filesRes.ok) {
        const fData = await filesRes.json();
        setFilesData(fData.files || []);
        if (fData.files && fData.files.length > 0) {
          setSelectedFile(fData.files[0]);
        }
      }
    } catch (err) {
      console.error("Error loading scan results:", err);
    }
  };

  // Select a finding to inspect
  const handleOpenFinding = async (findingId) => {
    try {
      const res = await fetch(`${API_BASE}/api/finding/${findingId}`);
      if (res.ok) {
        const f = await res.json();
        setSelectedFinding(f);
        setActiveBlockIndex(0);
        setView("finding");
      }
    } catch (e) {
      alert("Failed to load finding details: " + e.message);
    }
  };

  // Fetch block explanation
  const handleFetchBlock = async (index) => {
    if (!selectedFinding) return;
    setLoadingBlock(true);
    try {
      const res = await fetch(`${API_BASE}/api/finding/${selectedFinding.id}/explain?block=${index}`);
      if (res.ok) {
        const data = await res.json();
        // Update local selected finding blocks
        const updated = { ...selectedFinding };
        if (updated.explanation && updated.explanation.blocks) {
          updated.explanation.blocks[index] = data.block;
        }
        setSelectedFinding(updated);
        setActiveBlockIndex(index);
      }
    } catch (e) {
      console.error("Block explanation error:", e);
    } finally {
      setLoadingBlock(false);
    }
  };

  // Request fix remediation
  const handleRequestFix = async () => {
    if (!selectedFinding) return;
    setFixLoading(true);
    try {
      const res = await fetch(`${API_BASE}/api/finding/${selectedFinding.id}/fix`, {
        method: "POST",
      });
      if (res.ok) {
        const data = await res.json();
        setSelectedFinding((prev) => ({
          ...prev,
          fix_diff: data.diff,
          validation: data.validation,
        }));
      }
    } catch (e) {
      alert("Failed to generate fix: " + e.message);
    } finally {
      setFixLoading(false);
    }
  };

  // Render Mermaid flowchart
  useEffect(() => {
    if (view === "finding" && selectedFinding && selectedFinding.flow_mermaid && mermaidRef.current) {
      const code = selectedFinding.flow_mermaid;
      const containerId = "mermaid-flow-" + Math.floor(Math.random() * 100000);
      try {
        mermaid.render(containerId, code).then(({ svg }) => {
          if (mermaidRef.current) {
            mermaidRef.current.innerHTML = svg;
          }
        }).catch((err) => {
          if (mermaidRef.current) {
            mermaidRef.current.innerHTML = `<pre style="color:#ef4444; font-size:12px;">Failed to render Mermaid chart: ${err.message}</pre>`;
          }
        });
      } catch (err) {
        if (mermaidRef.current) {
          mermaidRef.current.innerHTML = `<pre style="color:#ef4444;">${err}</pre>`;
        }
      }
    }
  }, [view, selectedFinding]);

  // Send chat message
  const handleSendChat = async (e) => {
    if (e) e.preventDefault();
    if (!chatInput.trim() || !activeScanId) return;

    const userText = chatInput.trim();
    setChatInput("");
    setChatMessages((prev) => [...prev, { sender: "user", text: userText }]);
    setChatLoading(true);

    try {
      const res = await fetch(`${API_BASE}/api/scan/${activeScanId}/chat`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ message: userText }),
      });
      if (res.ok) {
        const data = await res.json();
        setChatMessages((prev) => [
          ...prev,
          {
            sender: "assistant",
            text: data.answer,
            intent: data.intent,
            sources: data.sources || [],
          },
        ]);
      }
    } catch (e) {
      setChatMessages((prev) => [
        ...prev,
        {
          sender: "assistant",
          text: "Error reaching chat assistant: " + e.message,
          intent: "error",
          sources: [],
        },
      ]);
    } finally {
      setChatLoading(false);
    }
  };

  // Filtered findings list
  const filteredFindings = findings.filter((f) => {
    if (filterSeverity !== "ALL" && f.severity.toUpperCase() !== filterSeverity) return false;
    if (filterLang !== "ALL" && f.language !== filterLang) return false;
    return true;
  });

  return (
    <div className="app-container">
      {/* Navigation Bar */}
      <header className="navbar">
        <div className="nav-brand" onClick={() => setView("home")}>
          <span className="brand-logo">VulnExplain</span>
          <span className="brand-badge">GraphCodeBERT + AST</span>
        </div>
        <nav className="nav-links">
          <button className={`nav-btn ${view === "home" ? "active" : ""}`} onClick={() => setView("home")}>
            New Scan
          </button>
          {activeScanId && (
            <>
              <button className={`nav-btn ${view === "dashboard" ? "active" : ""}`} onClick={() => setView("dashboard")}>
                Findings ({findings.length})
              </button>
              <button className={`nav-btn ${view === "explorer" ? "active" : ""}`} onClick={() => setView("explorer")}>
                Code Explorer
              </button>
              <button className={`nav-btn ${view === "chat" ? "active" : ""}`} onClick={() => setView("chat")}>
                Assistant
              </button>
            </>
          )}
        </nav>
      </header>

      {/* Main Content Area */}
      <main className="main-content">
        {/* VIEW 1: HOME */}
        {view === "home" && (
          <div>
            <section className="hero-section">
              <h1 className="hero-title">Repository Vulnerability Intelligence</h1>
              <p className="hero-subtitle">
                Fine-tuned GraphCodeBERT detector with AST-grounded vulnerability flows,
                block-by-block LLM explanations, and automated diff remediation.
              </p>
              <div className="scan-box">
                <form className="scan-form" onSubmit={handleStartScan}>
                  <input
                    type="text"
                    className="scan-input"
                    placeholder="Enter public GitHub repository URL (e.g. https://github.com/owner/repo)"
                    value={repoUrl}
                    onChange={(e) => setRepoUrl(e.target.value)}
                  />
                  <button type="submit" className="btn-primary" disabled={!repoUrl.trim()}>
                    Scan Repo
                  </button>
                </form>
              </div>
            </section>

            <section className="recent-scans-card">
              <h2 className="card-title">Recent Repository Scans</h2>
              {recentScans.length === 0 ? (
                <p style={{ color: "var(--text-muted)" }}>No recent scans found. Start by scanning a repository above.</p>
              ) : (
                <table className="scans-table">
                  <thead>
                    <tr>
                      <th>Scan ID</th>
                      <th>Repository</th>
                      <th>Status</th>
                      <th>Findings</th>
                      <th>Date</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentScans.map((s) => (
                      <tr
                        key={s.id}
                        onClick={async () => {
                          setActiveScanId(s.id);
                          await loadScanResults(s.id);
                          setView("dashboard");
                        }}
                      >
                        <td style={{ fontFamily: "var(--font-mono)", color: "var(--accent-blue)" }}>{s.id.slice(0, 14)}</td>
                        <td>{s.repo_url}</td>
                        <td>
                          <span className={`badge badge-status-${s.status}`}>{s.status}</span>
                        </td>
                        <td>{s.summary?.flagged_functions ?? 0} flagged</td>
                        <td style={{ color: "var(--text-muted)" }}>{s.created_at?.slice(0, 16)}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </section>
          </div>
        )}

        {/* VIEW 2: PROGRESS */}
        {view === "progress" && (
          <div className="progress-container">
            <h2>Analyzing Repository...</h2>
            <p style={{ color: "var(--text-secondary)", marginTop: "0.5rem" }}>
              Executing 9-stage code intelligence pipeline on <code>{scanData?.repo_url || repoUrl}</code>
            </p>
            <div className="progress-bar-bg">
              <div className="progress-bar-fill" style={{ width: `${scanData?.progress || 10}%` }}></div>
            </div>
            <p style={{ fontWeight: 600, color: "var(--accent-blue)" }}>
              {scanData?.progress || 10}% Complete
            </p>
            {scanData?.status === "failed" && (
              <div style={{ marginTop: "1rem", color: "var(--accent-red)" }}>
                Scan failed: {scanData.error_message || "Unknown error"}
                <br />
                <button className="btn-secondary" style={{ marginTop: "0.75rem" }} onClick={() => setView("home")}>
                  Return to Home
                </button>
              </div>
            )}
          </div>
        )}

        {/* VIEW 3: RESULTS DASHBOARD */}
        {view === "dashboard" && (
          <div>
            <div className="summary-grid">
              <div className="summary-card">
                <div className="summary-card-title">Scanned Functions</div>
                <div className="summary-card-val">{scanData?.summary?.total_functions ?? 0}</div>
              </div>
              <div className="summary-card">
                <div className="summary-card-title">Flagged Vulnerabilities</div>
                <div className="summary-card-val" style={{ color: "var(--severity-critical)" }}>
                  {findings.length}
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-title">Critical Severity</div>
                <div className="summary-card-val" style={{ color: "var(--severity-critical)" }}>
                  {scanData?.summary?.by_severity?.Critical ?? 0}
                </div>
              </div>
              <div className="summary-card">
                <div className="summary-card-title">High / Medium</div>
                <div className="summary-card-val" style={{ color: "var(--severity-high)" }}>
                  {(scanData?.summary?.by_severity?.High ?? 0) + (scanData?.summary?.by_severity?.Medium ?? 0)}
                </div>
              </div>
            </div>

            <div className="recent-scans-card">
              <div className="toolbar">
                <h2 className="card-title">Detected Vulnerabilities</h2>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <select className="filter-select" value={filterSeverity} onChange={(e) => setFilterSeverity(e.target.value)}>
                    <option value="ALL">All Severities</option>
                    <option value="CRITICAL">Critical</option>
                    <option value="HIGH">High</option>
                    <option value="MEDIUM">Medium</option>
                    <option value="LOW">Low</option>
                  </select>
                  <select className="filter-select" value={filterLang} onChange={(e) => setFilterLang(e.target.value)}>
                    <option value="ALL">All Languages</option>
                    <option value="python">Python</option>
                    <option value="javascript">JavaScript</option>
                    <option value="c">C</option>
                    <option value="cpp">C++</option>
                    <option value="java">Java</option>
                    <option value="go">Go</option>
                    <option value="csharp">C#</option>
                  </select>
                </div>
              </div>

              {filteredFindings.length === 0 ? (
                <p style={{ color: "var(--text-muted)", padding: "1.5rem 0" }}>
                  No vulnerabilities match the chosen criteria.
                </p>
              ) : (
                <table className="scans-table">
                  <thead>
                    <tr>
                      <th>File & Line</th>
                      <th>Function</th>
                      <th>CWE Type</th>
                      <th>Severity</th>
                      <th>Confidence</th>
                      <th>Action</th>
                    </tr>
                  </thead>
                  <tbody>
                    {filteredFindings.map((f) => (
                      <tr key={f.id} onClick={() => handleOpenFinding(f.id)}>
                        <td style={{ fontFamily: "var(--font-mono)" }}>
                          {f.file}:{f.start_line}
                        </td>
                        <td style={{ fontWeight: 600 }}>{f.func_name}</td>
                        <td>
                          <span style={{ color: "var(--accent-indigo)", fontWeight: 500 }}>{f.cwe}</span>
                        </td>
                        <td>
                          <span className={`badge badge-severity-${f.severity.toLowerCase()}`}>{f.severity}</span>
                        </td>
                        <td>{(f.prob * 100).toFixed(1)}%</td>
                        <td>
                          <button className="btn-secondary" onClick={() => handleOpenFinding(f.id)}>
                            Inspect
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              )}
            </div>
          </div>
        )}

        {/* VIEW 4: FINDING DETAIL */}
        {view === "finding" && selectedFinding && (
          <div>
            <div style={{ marginBottom: "1rem", display: "flex", justifyContent: "space-between", alignItems: "center" }}>
              <button className="btn-secondary" onClick={() => setView("dashboard")}>
                ← Back to Findings
              </button>
              <div style={{ display: "flex", gap: "0.5rem", alignItems: "center" }}>
                <span className={`badge badge-severity-${selectedFinding.severity.toLowerCase()}`}>
                  {selectedFinding.severity}
                </span>
                <span className="brand-badge">{selectedFinding.cwe}</span>
                <span style={{ color: "var(--text-muted)", fontSize: "0.85rem" }}>
                  Prob: {(selectedFinding.prob * 100).toFixed(1)}%
                </span>
              </div>
            </div>

            <div className="finding-detail-grid">
              {/* Left Panel: Code & Localized Suspicious Sinks */}
              <div className="panel">
                <div className="panel-header">
                  <h3>
                    <code>{selectedFinding.file}:{selectedFinding.start_line}</code>
                  </h3>
                  <span style={{ fontSize: "0.8rem", color: "var(--text-muted)" }}>{selectedFinding.language}</span>
                </div>

                <div className="code-viewer">
                  {selectedFinding.code.split("\n").map((line, idx) => {
                    const currentAbsLine = selectedFinding.start_line + idx;
                    const isSuspicious = selectedFinding.suspicious_lines?.some(
                      (sl) => sl.line === currentAbsLine
                    );
                    return (
                      <div key={idx} className={`code-line ${isSuspicious ? "line-suspicious" : ""}`}>
                        <span className="code-line-num">{currentAbsLine}</span>
                        <span className="code-line-content">{line}</span>
                      </div>
                    );
                  })}
                </div>

                {selectedFinding.suspicious_lines && selectedFinding.suspicious_lines.length > 0 && (
                  <div style={{ background: "rgba(239, 68, 68, 0.08)", padding: "0.75rem", borderRadius: "0.5rem", border: "1px solid rgba(239, 68, 68, 0.2)" }}>
                    <div style={{ fontWeight: 600, color: "var(--severity-critical)", fontSize: "0.8rem", marginBottom: "0.25rem" }}>
                      SUSPICIOUS SINK DETECTED
                    </div>
                    {selectedFinding.suspicious_lines.map((sl, i) => (
                      <div key={i} style={{ fontSize: "0.8rem", color: "#fca5a5" }}>
                        Line {sl.line}: {sl.reason}
                      </div>
                    ))}
                  </div>
                )}

                {/* Diff & Validation Display (if fix generated) */}
                {selectedFinding.validation?.fix_message && (
                  <p role="status">{selectedFinding.validation.fix_message}</p>
                )}
                {selectedFinding.fix_diff ? (
                  <div>
                    <h4 style={{ margin: "1rem 0 0.5rem" }}>Remediation Diff & Validation</h4>
                    <div className="diff-viewer">
                      {selectedFinding.fix_diff.split("\n").map((dline, di) => {
                        let cl = "";
                        if (dline.startsWith("+") && !dline.startsWith("+++")) cl = "diff-add";
                        if (dline.startsWith("-") && !dline.startsWith("---")) cl = "diff-del";
                        return <div key={di} className={cl}>{dline}</div>;
                      })}
                    </div>
                    {selectedFinding.validation?.verdict && (
                      <div className="validation-card" style={{ marginTop: "0.75rem" }}>
                        <div style={{ display: "flex", justifyContent: "space-between", marginBottom: "0.5rem" }}>
                          <span>Verdict: <span className={`val-badge-${selectedFinding.validation.verdict}`}>{selectedFinding.validation.verdict?.toUpperCase()}</span></span>
                          <span>Prob: {selectedFinding.validation.prob_before} → <b>{selectedFinding.validation.prob_after}</b></span>
                        </div>
                        <div style={{ fontSize: "0.8rem", color: "var(--text-secondary)" }}>
                          Syntax: {selectedFinding.validation.syntax_ok ? "✓ Valid AST" : "✗ Parse Issue"} ({selectedFinding.validation.syntax_message})
                        </div>
                        <div style={{ fontSize: "0.75rem", color: "var(--text-muted)", marginTop: "0.5rem", fontStyle: "italic" }}>
                          {selectedFinding.validation.disclaimer}
                        </div>
                      </div>
                    )}
                  </div>
                ) : (
                  <button className="btn-primary" style={{ marginTop: "0.5rem" }} onClick={handleRequestFix} disabled={fixLoading}>
                    {fixLoading ? "Generating Patch & Validating..." : "Suggest Automated Fix"}
                  </button>
                )}
              </div>

              {/* Right Panel: Progressive Explanation & Mermaid Flow */}
              <div className="panel">
                <div className="panel-header">
                  <h3>Vulnerability Flow & Explanation</h3>
                </div>

                {/* Overall Summary */}
                {selectedFinding.explanation?.summary && (
                  <div style={{ background: "rgba(51, 65, 85, 0.3)", padding: "0.75rem", borderRadius: "0.5rem", fontSize: "0.85rem" }}>
                    <div style={{ marginBottom: "0.4rem" }}>
                      <b>Functionality:</b> {selectedFinding.explanation.summary.what_it_does}
                    </div>
                    <div style={{ marginBottom: "0.4rem" }}>
                      <b>Vulnerability Mechanism:</b> {selectedFinding.explanation.summary.why_vulnerable}
                    </div>
                    <div>
                      <b>Security Impact:</b> {selectedFinding.explanation.summary.impact}
                    </div>
                  </div>
                )}

                {/* Progressive Block Disclosure */}
                {selectedFinding.explanation?.blocks && selectedFinding.explanation.blocks.length > 0 && (
                  <div className="block-stepper">
                    <div className="block-stepper-header">
                      <span style={{ fontWeight: 600, fontSize: "0.85rem" }}>
                        Block {activeBlockIndex + 1} of {selectedFinding.explanation.blocks.length} (Lines {selectedFinding.explanation.blocks[activeBlockIndex]?.start_line}-{selectedFinding.explanation.blocks[activeBlockIndex]?.end_line})
                      </span>
                      <div style={{ display: "flex", gap: "0.5rem" }}>
                        <button
                          className="btn-secondary"
                          disabled={activeBlockIndex === 0}
                          onClick={() => handleFetchBlock(activeBlockIndex - 1)}
                        >
                          Previous
                        </button>
                        <button
                          className="btn-secondary"
                          disabled={activeBlockIndex >= selectedFinding.explanation.blocks.length - 1}
                          onClick={() => handleFetchBlock(activeBlockIndex + 1)}
                        >
                          Next Part →
                        </button>
                      </div>
                    </div>
                    <div style={{ fontSize: "0.85rem", color: "var(--text-secondary)", minHeight: "60px" }}>
                      {loadingBlock ? (
                        <em>Generating block explanation...</em>
                      ) : (
                        selectedFinding.explanation.blocks[activeBlockIndex]?.explanation || (
                          <button className="btn-secondary" onClick={() => handleFetchBlock(activeBlockIndex)}>
                            Explain this block
                          </button>
                        )
                      )}
                    </div>
                  </div>
                )}

                {/* Program Analysis Flowchart */}
                <h4 style={{ marginTop: "0.5rem" }}>Static Program Flow (AST & Def-Use)</h4>
                <div className="mermaid-box" ref={mermaidRef}>
                  <em>Rendering program analysis flow...</em>
                </div>
              </div>
            </div>
          </div>
        )}

        {/* VIEW 5: CODE EXPLORER */}
        {view === "explorer" && (
          <div className="explorer-container">
            <div className="file-tree">
              <h3 style={{ fontSize: "0.9rem", color: "var(--text-muted)", marginBottom: "0.75rem" }}>FILES</h3>
              {filesData.map((file, i) => (
                <div
                  key={i}
                  className={`file-item ${selectedFile?.path === file.path ? "selected" : ""}`}
                  onClick={() => setSelectedFile(file)}
                >
                  <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>
                    {file.path}
                  </span>
                  {file.vuln_count > 0 && (
                    <span className="file-vuln-indicator">{file.vuln_count}</span>
                  )}
                </div>
              ))}
            </div>

            <div className="file-preview">
              <div style={{ padding: "0.75rem 1rem", borderBottom: "1px solid var(--border-color)", display: "flex", justifyContent: "space-between" }}>
                <span style={{ fontFamily: "var(--font-mono)", fontWeight: 600 }}>{selectedFile?.path}</span>
                <span style={{ color: "var(--text-muted)", fontSize: "0.8rem" }}>{selectedFile?.lines} lines | {selectedFile?.language}</span>
              </div>
              <div className="code-viewer" style={{ flex: 1, maxHeight: "none", borderRadius: 0 }}>
                {selectedFile?.content ? (
                  selectedFile.content.split("\n").map((line, idx) => (
                    <div key={idx} className="code-line">
                      <span className="code-line-num">{idx + 1}</span>
                      <span className="code-line-content">{line}</span>
                    </div>
                  ))
                ) : (
                  <p style={{ padding: "1rem", color: "var(--text-muted)" }}>Select a file to view code.</p>
                )}
              </div>
            </div>
          </div>
        )}

        {/* VIEW 6: CHAT ASSISTANT */}
        {view === "chat" && (
          <div className="chat-container">
            <div className="chat-messages">
              {chatMessages.map((msg, i) => (
                <div key={i} className={`chat-bubble bubble-${msg.sender}`}>
                  <div>{msg.text}</div>
                  {msg.intent && msg.intent !== "greeting" && (
                    <div className="chat-meta">
                      <span>Intent: <b>{msg.intent}</b></span>
                      {msg.sources && msg.sources.length > 0 && (
                        <span>
                          Sources:{" "}
                          {msg.sources.map((s, si) => (
                            <span key={si} className="chat-source-tag">{s}</span>
                          ))}
                        </span>
                      )}
                    </div>
                  )}
                </div>
              ))}
              {chatLoading && (
                <div className="chat-bubble bubble-assistant">
                  <em>Retrieving repository context and formulating answer...</em>
                </div>
              )}
            </div>

            <form className="chat-input-bar" onSubmit={handleSendChat}>
              <input
                type="text"
                className="scan-input"
                placeholder="Ask about vulnerabilities, flows, patches, or repo architecture..."
                value={chatInput}
                onChange={(e) => setChatInput(e.target.value)}
              />
              <button type="submit" className="btn-primary" disabled={!chatInput.trim() || chatLoading}>
                Send
              </button>
            </form>
          </div>
        )}
      </main>

      {/* Footer Disclaimer */}
      <footer className="footer-disclaimer">
        NOTICE: AI explanations and automated fixes may be incorrect; validation is probabilistic. Always review changes manually.
      </footer>
    </div>
  );
}
