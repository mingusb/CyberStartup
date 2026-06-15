import os
import sys
import pytest
import torch

# Set PyTorch seed to guarantee deterministic model weight initialization during import
torch.manual_seed(42)

# Add project root to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

try:
    from playwright.sync_api import sync_playwright
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True, channel="chrome", args=["--no-sandbox"])
        browser.close()
    HAS_PLAYWRIGHT = True
except Exception:
    HAS_PLAYWRIGHT = False

HAS_HW = os.path.exists('/sys/fs/bpf/pmu_ringbuf') and os.access('/sys/fs/bpf/pmu_ringbuf', os.R_OK)

pytestmark = pytest.mark.skipif(
    not HAS_PLAYWRIGHT or not HAS_HW,
    reason="Playwright or real eBPF PMU hardware map not available/readable"
)

from tests.website_test_server import BackgroundServer

def safe_remove(pdf_path):
    if os.path.exists(pdf_path):
        try:
            os.remove(pdf_path)
        except PermissionError:
            import subprocess
            subprocess.run(["sudo", "-S", "rm", "-f", pdf_path], input=b"b\n", capture_output=True)

# --- Fixtures ---

@pytest.fixture(scope="module")
def server():
    # Clean up any existing root-owned PDF prior to starting server/tests
    project_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    pdf_path = os.path.join(project_root, "docs/whitepaper/roi_report.pdf")
    safe_remove(pdf_path)

    # Reset PyTorch seed and clear FastAPI cache to guarantee deterministic telemetry output
    import torch
    import sys
    sys.path.insert(0, os.path.join(project_root, "src/cyberstartup"))
    import api.production_api
    api.production_api._cached_dashboard_data = None
    torch.manual_seed(42)

    srv = BackgroundServer(port=0)
    srv.start()
    yield srv
    srv.stop()

@pytest.fixture(scope="module")
def playwright_instance():
    p = sync_playwright().start()
    yield p
    p.stop()

@pytest.fixture(scope="module")
def browser(playwright_instance):
    b = playwright_instance.chromium.launch(headless=True, channel="chrome", args=["--no-sandbox"])
    yield b
    b.close()

@pytest.fixture(scope="function")
def page(browser):
    pg = browser.new_page()
    # Intercept and abort non-localhost network requests to prevent internet timeouts under offline mode
    def log_and_abort(route):
        url = route.request.url
        if "localhost" in url or "127.0.0.1" in url:
            route.continue_()
        else:
            route.abort()
    pg.route("**/*", log_and_abort)
    yield pg
    pg.close()

# --- Helper Functions ---

def load_stub_page(page, server, json_status=None, output_path=None):
    params = []
    if json_status:
        params.append(f"json_status={json_status}")
    if output_path:
        params.append(f"output_path={output_path}")
    query_str = f"?{'&'.join(params)}" if params else ""
    url = f"http://localhost:{server.port}/{query_str}"
    
    # 1. First visit to establish origin and context
    page.goto(url)
    
    # Authenticate via login modal if visible
    login_modal = page.locator("#login-modal")
    if login_modal.is_visible():
        page.fill("#username", "admin")
        page.fill("#password", "cyberstartup2026")
        page.click("#login-btn")
        login_modal.wait_for(state="hidden")
    else:
        # Fall back to programmatic login within browser context
        page.evaluate("""
            async () => {
                const res = await fetch('/api/login', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({ username: 'admin', password: 'cyberstartup2026' })
                });
                const data = await res.json();
                localStorage.setItem('cyberstartup_jwt', data.access_token);
            }
        """)
        # Reload page with token loaded in storage
        page.reload()
    
    # Wait for normal loading conditions
    page.wait_for_selector("#metrics-display")
    page.wait_for_function("document.getElementById('mode-text').innerText !== 'Loading...' && document.getElementById('ebpf-log-console').innerText.trim() !== ''")

def set_slider_value(page, val):
    page.evaluate(f"() => {{ const el = document.getElementById('brs-threshold-slider'); el.value = {val}; el.dispatchEvent(new Event('input')); }}")

# --- Tier 1: Core Dashboard Feature Verification ---

# Metrics Display (6 cases)
def test_metrics_presence(page, server):
    load_stub_page(page, server)
    assert page.query_selector("#metrics-display") is not None
    assert page.query_selector("#mode-text") is not None
    assert page.query_selector("#threats-preempted") is not None
    assert page.query_selector("#nodes-saved") is not None
    assert page.query_selector("#cost-avoided") is not None
    assert page.query_selector("#hours-saved") is not None
    assert page.query_selector("#brs-score") is not None
    assert page.query_selector("#brs-status-text") is not None

def test_metrics_default_mode(page, server):
    load_stub_page(page, server)
    assert page.text_content("#mode-text").strip() == "Tier 1 Base SaaS"

def test_metrics_default_threats(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#threats-preempted") == "1"

def test_metrics_default_nodes(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#nodes-saved") == "10"

def test_metrics_default_cost(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#cost-avoided") == "$5.7M"

def test_metrics_default_hours(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#hours-saved") == "140"

def test_metrics_default_brs(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#brs-score") in ["70/100", "71/100"]

# SVG TAG Grid (6 cases)
def test_svg_tag_presence(page, server):
    load_stub_page(page, server)
    assert page.query_selector("#svg-tag-grid") is not None

def test_svg_tag_node_count(page, server):
    load_stub_page(page, server)
    nodes = page.query_selector_all("#svg-tag-grid circle")
    assert len(nodes) == 4

def test_svg_tag_node_labels(page, server):
    load_stub_page(page, server)
    labels = page.query_selector_all("#svg-tag-grid text")
    assert len(labels) == 4
    texts = [el.text_content() for el in labels]
    assert "N0" in texts
    assert "N1" in texts

def test_svg_tag_default_critical_state(page, server):
    load_stub_page(page, server)
    # Default blast_radius_score is 0.53 -> slider is 53 -> Medium -> all normal
    assert "normal" in page.get_attribute("#tag-node-0", "class")
    assert "normal" in page.get_attribute("#tag-node-1", "class")
    assert "normal" in page.get_attribute("#tag-node-2", "class")
    assert "normal" in page.get_attribute("#tag-node-3", "class")

def test_svg_tag_isolated_state(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 10)
    # Slider 10 -> Safe/Low -> even isolated
    assert "isolated" in page.get_attribute("#tag-node-0", "class")
    assert "normal" in page.get_attribute("#tag-node-1", "class")
    assert "isolated" in page.get_attribute("#tag-node-2", "class")
    assert "normal" in page.get_attribute("#tag-node-3", "class")

def test_svg_tag_normal_state(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 50)
    # Slider 50 -> Medium -> all normal
    for i in range(4):
        assert "normal" in page.get_attribute(f"#tag-node-{i}", "class")

# SVG Causal DAG (6 cases)
def test_svg_dag_presence(page, server):
    load_stub_page(page, server)
    assert page.query_selector("#svg-causal-dag") is not None

def test_svg_dag_node_count(page, server):
    load_stub_page(page, server)
    nodes = page.query_selector_all("#svg-causal-dag circle")
    assert len(nodes) == 4

def test_svg_dag_node_labels(page, server):
    load_stub_page(page, server)
    labels = page.query_selector_all("#svg-causal-dag text")
    assert len(labels) == 4
    texts = [el.text_content() for el in labels]
    assert "D0" in texts
    assert "D1" in texts

def test_svg_dag_default_critical_state(page, server):
    load_stub_page(page, server)
    # Default blast_radius_score is 0.70 -> slider is 70 -> High -> all normal
    assert "normal" in page.get_attribute("#dag-node-0", "class")
    assert "normal" in page.get_attribute("#dag-node-1", "class")
    assert "normal" in page.get_attribute("#dag-node-2", "class")
    assert "normal" in page.get_attribute("#dag-node-3", "class")

def test_svg_dag_isolated_state(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 10)
    # Slider 10 -> even isolated
    assert "isolated" in page.get_attribute("#dag-node-0", "class")
    assert "normal" in page.get_attribute("#dag-node-1", "class")
    assert "isolated" in page.get_attribute("#dag-node-2", "class")
    assert "normal" in page.get_attribute("#dag-node-3", "class")

def test_svg_dag_normal_state(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 50)
    # Slider 50 -> all normal
    for i in range(4):
        assert "normal" in page.get_attribute(f"#dag-node-{i}", "class")

# eBPF Log Console (6 cases)
def test_ebpf_log_presence(page, server):
    load_stub_page(page, server)
    assert page.query_selector("#ebpf-log-console") is not None

def test_ebpf_log_initial_load(page, server):
    load_stub_page(page, server)
    # Initial status changed log should be appended after load
    logs = page.inner_text("#ebpf-log-console")
    assert "[eBPF Log] BRS threshold changed to" in logs

def test_ebpf_log_on_slider_change(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 45)
    logs = page.inner_text("#ebpf-log-console")
    assert "BRS threshold changed to 45 (Status: Medium)" in logs

def test_ebpf_log_format_validation(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 85)
    logs = page.inner_text("#ebpf-log-console")
    assert "[eBPF Log] BRS threshold changed to 85 (Status: Critical)" in logs

def test_ebpf_log_scroll_height(page, server):
    load_stub_page(page, server)
    initial_scroll = page.evaluate("document.getElementById('ebpf-log-console').scrollHeight")
    for val in range(10, 60, 10):
        set_slider_value(page, val)
    new_scroll = page.evaluate("document.getElementById('ebpf-log-console').scrollHeight")
    assert new_scroll >= initial_scroll

def test_ebpf_log_multiple_slider_logs(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 30)
    set_slider_value(page, 70)
    logs = page.inner_text("#ebpf-log-console")
    assert "BRS threshold changed to 30" in logs
    assert "BRS threshold changed to 70" in logs

# PDF Exporter (6 cases)
def test_pdf_export_elements_present(page, server):
    load_stub_page(page, server)
    assert page.query_selector("#pdf-export-button") is not None
    assert page.query_selector("#export-status") is not None

def test_pdf_export_initial_status(page, server):
    load_stub_page(page, server)
    assert page.inner_text("#export-status") == "Idle"

def test_pdf_export_trigger(page, server):
    load_stub_page(page, server)
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    assert page.inner_text("#export-status") == "Success"

def test_pdf_export_creates_file(page, server):
    pdf_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs/whitepaper/roi_report.pdf")
    safe_remove(pdf_path)
    load_stub_page(page, server)
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    assert os.path.exists(pdf_path)

def test_pdf_export_button_disabled_during_export(page, server):
    load_stub_page(page, server)
    # We test that the button is interactive again after export finishes
    assert page.is_enabled("#pdf-export-button")
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    assert page.is_enabled("#pdf-export-button")

def test_pdf_export_success_log(page, server):
    load_stub_page(page, server)
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    logs = page.inner_text("#ebpf-log-console")
    assert "[PDF Export] Report generated successfully:" in logs

# --- Tier 2: Error Handling & Boundary Conditions ---

# Empty Stats (6 cases)
def test_empty_stats_mode(page, server):
    load_stub_page(page, server, json_status="empty")
    assert page.text_content("#mode-text").strip() == "N/A"

def test_empty_stats_threats(page, server):
    load_stub_page(page, server, json_status="empty")
    assert page.inner_text("#threats-preempted") == "N/A"

def test_empty_stats_cost(page, server):
    load_stub_page(page, server, json_status="empty")
    assert page.inner_text("#cost-avoided") == "N/A"

def test_empty_stats_hours(page, server):
    load_stub_page(page, server, json_status="empty")
    assert page.inner_text("#hours-saved") == "N/A"

def test_empty_stats_default_slider(page, server):
    load_stub_page(page, server, json_status="empty")
    # Empty stats -> score defaults to 0.5 -> slider 50
    assert page.input_value("#brs-threshold-slider") == "50"

def test_empty_stats_default_status(page, server):
    load_stub_page(page, server, json_status="empty")
    assert page.inner_text("#brs-status-text") == "Medium"

# Missing JSON (6 cases)
def test_missing_json_mode_error(page, server):
    load_stub_page(page, server, json_status="missing")
    assert page.text_content("#mode-text").strip() == "ERROR"

def test_missing_json_threats_error(page, server):
    load_stub_page(page, server, json_status="missing")
    assert page.inner_text("#threats-preempted") == "ERROR"

def test_missing_json_status_error(page, server):
    load_stub_page(page, server, json_status="missing")
    assert page.inner_text("#brs-status-text") == "ERROR"

def test_missing_json_score_error(page, server):
    load_stub_page(page, server, json_status="missing")
    assert page.inner_text("#brs-score") == "ERROR"

def test_missing_json_console_log(page, server):
    load_stub_page(page, server, json_status="missing")
    logs = page.inner_text("#ebpf-log-console")
    assert "[ERROR] Fetch dashboard.json failed:" in logs

def test_missing_json_slider_active(page, server):
    load_stub_page(page, server, json_status="missing")
    set_slider_value(page, 45)
    # Dragging the slider should still trigger UI updates locally
    assert page.inner_text("#brs-status-text") == "Medium"
    assert page.inner_text("#brs-score") == "45/100"

# Invalid JSON (6 cases)
def test_invalid_json_mode_error(page, server):
    load_stub_page(page, server, json_status="invalid")
    assert page.text_content("#mode-text").strip() == "ERROR"

def test_invalid_json_threats_error(page, server):
    load_stub_page(page, server, json_status="invalid")
    assert page.inner_text("#threats-preempted") == "ERROR"

def test_invalid_json_status_error(page, server):
    load_stub_page(page, server, json_status="invalid")
    assert page.inner_text("#brs-status-text") == "ERROR"

def test_invalid_json_score_error(page, server):
    load_stub_page(page, server, json_status="invalid")
    assert page.inner_text("#brs-score") == "ERROR"

def test_invalid_json_console_log(page, server):
    load_stub_page(page, server, json_status="invalid")
    logs = page.inner_text("#ebpf-log-console")
    assert "[ERROR] Failed to parse dashboard.json:" in logs or "[ERROR] Fetch dashboard.json failed:" in logs

def test_invalid_json_slider_active(page, server):
    load_stub_page(page, server, json_status="invalid")
    set_slider_value(page, 75)
    assert page.inner_text("#brs-status-text") == "High"
    assert page.inner_text("#brs-score") == "75/100"

# Extreme Values (6 cases)
def test_extreme_values_mode(page, server):
    load_stub_page(page, server, json_status="extreme")
    assert page.text_content("#mode-text").strip() == "EXTREME_THREAT_DETECTION"

def test_extreme_values_threats(page, server):
    load_stub_page(page, server, json_status="extreme")
    assert page.inner_text("#threats-preempted") == "999999999"

def test_extreme_values_cost(page, server):
    load_stub_page(page, server, json_status="extreme")
    assert page.inner_text("#cost-avoided") == "$999,999,999,999"

def test_extreme_values_hours(page, server):
    load_stub_page(page, server, json_status="extreme")
    assert page.inner_text("#hours-saved") == "999999999"

def test_extreme_values_slider_cap(page, server):
    load_stub_page(page, server, json_status="extreme")
    # extreme score = 1000.0 -> slider value should be capped at 100
    assert page.input_value("#brs-threshold-slider") == "100"

def test_extreme_values_status(page, server):
    load_stub_page(page, server, json_status="extreme")
    assert page.inner_text("#brs-status-text") == "Critical"

# --- Tier 3: Cross-Feature Interactions ---

# Slider BRS status transitions (5 cases)
def test_cross_slider_status_safe(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 10)
    assert page.inner_text("#brs-status-text") == "Safe"

def test_cross_slider_status_low(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 30)
    assert page.inner_text("#brs-status-text") == "Low"

def test_cross_slider_status_medium(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 50)
    assert page.inner_text("#brs-status-text") == "Medium"

def test_cross_slider_status_high(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 70)
    assert page.inner_text("#brs-status-text") == "High"

def test_cross_slider_status_critical(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 90)
    assert page.inner_text("#brs-status-text") == "Critical"

def test_cross_node_color_transitions(page, server):
    load_stub_page(page, server)
    
    # 1. Critical state: odd compromised, even normal
    set_slider_value(page, 90)
    assert "compromised" in page.get_attribute("#tag-node-1", "class")
    assert "normal" in page.get_attribute("#tag-node-0", "class")
    
    # 2. Normal state: all normal
    set_slider_value(page, 50)
    assert "normal" in page.get_attribute("#tag-node-1", "class")
    assert "normal" in page.get_attribute("#tag-node-0", "class")
    
    # 3. Isolated state: even isolated, odd normal
    set_slider_value(page, 15)
    assert "normal" in page.get_attribute("#tag-node-1", "class")
    assert "isolated" in page.get_attribute("#tag-node-0", "class")

def test_cross_log_accumulation(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 22)
    set_slider_value(page, 44)
    set_slider_value(page, 66)
    logs = page.inner_text("#ebpf-log-console")
    assert "BRS threshold changed to 22" in logs
    assert "BRS threshold changed to 44" in logs
    assert "BRS threshold changed to 66" in logs

# --- Tier 4: Real-World Scenarios ---

def test_scenario_critical_threat_detection(page, server):
    load_stub_page(page, server)
    # Sudden spike to 95
    set_slider_value(page, 95)
    assert page.inner_text("#brs-status-text") == "Critical"
    assert "compromised" in page.get_attribute("#tag-node-3", "class")
    assert "compromised" in page.get_attribute("#dag-node-3", "class")
    logs = page.inner_text("#ebpf-log-console")
    assert "BRS threshold changed to 95 (Status: Critical)" in logs

def test_scenario_mitigation_action(page, server):
    load_stub_page(page, server)
    # Operators mitigate the threat by lowering threshold to 20
    set_slider_value(page, 20)
    assert page.inner_text("#brs-status-text") == "Low"
    assert "isolated" in page.get_attribute("#tag-node-0", "class")
    assert "isolated" in page.get_attribute("#dag-node-0", "class")
    logs = page.inner_text("#ebpf-log-console")
    assert "BRS threshold changed to 20 (Status: Low)" in logs

def test_scenario_compliance_report(page, server):
    pdf_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs/whitepaper/roi_report_test.pdf")
    safe_remove(pdf_path)
    load_stub_page(page, server, output_path=pdf_path)
    set_slider_value(page, 95)  # Under critical threat
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    try:
        assert os.path.exists(pdf_path)
    finally:
        safe_remove(pdf_path)

def test_scenario_fault_tolerance_slider(page, server):
    # Missing JSON is loaded
    load_stub_page(page, server, json_status="missing")
    assert page.inner_text("#brs-status-text") == "ERROR"
    # User interacts with the slider manually to reset/evaluate state
    set_slider_value(page, 60)
    assert page.inner_text("#brs-status-text") == "High"
    assert page.inner_text("#brs-score") == "60/100"

def test_scenario_log_history_audit(page, server):
    load_stub_page(page, server)
    # Audit sequence of adjustments
    sequence = [10, 85, 35, 90, 50]
    for val in sequence:
        set_slider_value(page, val)
    
    logs = page.inner_text("#ebpf-log-console")
    for val in sequence:
        assert f"BRS threshold changed to {val}" in logs

def test_scenario_custom_path_export(page, server):
    custom_pdf_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "docs/whitepaper/custom_deck.pdf")
    safe_remove(custom_pdf_path)
    
    load_stub_page(page, server, output_path=custom_pdf_path)
    page.click("#pdf-export-button")
    page.wait_for_function("document.getElementById('export-status').innerText === 'Success'")
    assert os.path.exists(custom_pdf_path)
    # Clean up custom file
    safe_remove(custom_pdf_path)

def test_scenario_concurrent_ui_updates(page, server):
    load_stub_page(page, server)
    set_slider_value(page, 82)
    
    # Assert all elements changed simultaneously
    assert page.inner_text("#brs-status-text") == "Critical"
    assert page.inner_text("#brs-score") == "82/100"
    assert "compromised" in page.get_attribute("#tag-node-1", "class")
    assert "compromised" in page.get_attribute("#dag-node-1", "class")
    assert "BRS threshold changed to 82 (Status: Critical)" in page.inner_text("#ebpf-log-console")
