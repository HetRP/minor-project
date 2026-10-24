"""Browser acceptance checks against the real isolated API and existing React UI."""
import json
from pathlib import Path
from playwright.sync_api import sync_playwright, expect

ROOT = Path(__file__).resolve().parents[2]
OUT = ROOT / "results/integration"

def run():
    report = {"checks": {}, "page_errors": [], "console_errors": [], "failed_requests": []}
    checks = report["checks"]
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        page = browser.new_page(viewport={"width": 1440, "height": 1000})
        page.set_default_timeout(60000)
        page.on("pageerror", lambda error: report["page_errors"].append(str(error)))
        page.on("console", lambda message: report["console_errors"].append(message.text) if message.type == "error" else None)
        page.on("requestfailed", lambda request: report["failed_requests"].append({"url": request.url, "failure": request.failure}))
        api = "http://127.0.0.1:8765"
        assert page.request.get(api + "/api/health").json()["detector_loaded"]
        page.goto("http://127.0.0.1:5175")
        page.get_by_placeholder("Enter public GitHub repository URL", exact=False).fill(str(OUT / "unseen_repository_samples"))
        with page.expect_response(lambda r: r.url.endswith("/api/scan") and r.request.method == "POST") as response:
            page.get_by_role("button", name="Scan Repo", exact=True).click()
        scan_id = response.value.json()["scan_id"]
        expect(page.get_by_text("Scanned Functions", exact=True)).to_be_visible()
        checks["home_submit_progress_dashboard"] = True
        scan = page.request.get(f"{api}/api/scan/{scan_id}").json()
        findings = page.request.get(f"{api}/api/scan/{scan_id}/findings").json()
        assert scan["status"] == "done" and len(findings) == 6
        expect(page.locator("table tbody tr")).to_have_count(len(findings))
        for f in findings:
            row = page.locator("table tbody tr").filter(has_text=f["file"])
            expect(row).to_contain_text(f"{f['prob'] * 100:.1f}%")
            expect(row).to_contain_text(f["cwe"])
        checks["displayed_probabilities_cwes_and_counts_match_api"] = True
        page.locator("select").nth(1).select_option("javascript")
        expect(page.get_by_text("No vulnerabilities match", exact=False)).to_be_visible()
        page.locator("select").nth(1).select_option("python")
        expect(page.locator("table tbody tr")).to_have_count(6)
        checks["language_filter"] = True
        page.screenshot(path=str(OUT / "dashboard.png"), full_page=True)
        page.get_by_role("button", name="Inspect", exact=True).first.click()
        expect(page.get_by_text("Functionality:", exact=True)).to_be_visible()
        expect(page.locator(".mermaid-box svg")).to_be_visible()
        # Every graph from this real scan must actually render in Mermaid.
        first = findings[0]
        detail = page.request.get(f"{api}/api/finding/{first['id']}").json()
        expect(page.locator(".code-viewer").first).to_contain_text(detail["code"].splitlines()[0])
        checks["source_summary_and_mermaid_svg"] = True
        if len(detail["explanation"]["blocks"]) > 1:
            page.get_by_role("button", name="Next Part", exact=False).click()
            expect(page.get_by_text("Block 2 of", exact=False)).to_be_visible()
            checks["progressive_block_explanation"] = True
        page.get_by_role("button", name="Suggest Automated Fix", exact=True).click()
        expect(page.get_by_role("status")).to_contain_text("No executable patch was generated")
        expect(page.locator(".diff-viewer")).to_have_count(0)
        checks["unavailable_llm_patch_shown_honestly"] = True
        page.screenshot(path=str(OUT / "finding.png"), full_page=True)
        page.get_by_role("button", name="Code Explorer", exact=True).click()
        expect(page.locator(".file-item")).to_have_count(6)
        page.locator(".file-item").first.click()
        expect(page.locator(".file-preview .code-line").first).to_contain_text("def ")
        checks["code_explorer"] = True
        page.get_by_role("button", name="Assistant", exact=True).click()
        page.get_by_placeholder("Ask about vulnerabilities", exact=False).fill("What vulnerabilities were detected?")
        page.get_by_role("button", name="Send", exact=True).click()
        expect(page.locator(".chat-source-tag").first).to_be_visible()
        expect(page.get_by_text("vulnerability_query", exact=True)).to_be_visible()
        checks["chat_intent_and_citation_display"] = True
        page.get_by_role("button", name="Findings (6)", exact=True).click()
        for f in findings:
            page.locator("table tbody tr").filter(has_text=f["file"]).get_by_role("button", name="Inspect").click()
            expect(page.locator(".mermaid-box svg")).to_be_visible()
            page.get_by_role("button", name="Back to Findings", exact=False).click()
        checks["all_six_real_function_flowcharts_render"] = True
        report["scan_id"] = scan_id
        report["browser"] = browser.version
        report["status"] = "passed" if not report["page_errors"] and not report["console_errors"] else "errors"
        (OUT / "browser_verification.json").write_text(json.dumps(report, indent=2), encoding="utf-8")
        browser.close()
        print(json.dumps(report, indent=2))

if __name__ == "__main__":
    run()
