import streamlit as st
from ai_troubleshooter.rule_checker import load_all_cases, run

PASS_STATUSES = {"pass", "passed", "ok"}


def render_troubleshooter():
    """Render the AI-powered network troubleshooting panel."""
    st.markdown(
        '<div class="section-title">🤖 AI Network Troubleshooter</div>',
        unsafe_allow_html=True,
    )

    try:
        cases = load_all_cases()
    except Exception as error:
        st.error(f"Unable to load troubleshooting dataset: {error}")
        return

    if not cases:
        st.info("No troubleshooting cases available.")
        return

    cases_by_id = {case.case_id: case for case in cases}
    selected_case_id = st.selectbox(
        "Select Network Case",
        list(cases_by_id.keys()),
        key="troubleshooter_case",
    )
    selected_case = cases_by_id[selected_case_id]

    if st.button(
        "🔍 Run AI Troubleshooting",
        use_container_width=True,
        type="primary",
    ):
        with st.spinner("Analyzing network evidence..."):
            result = run(selected_case)
        st.session_state["troubleshooter_result"] = result

    result = st.session_state.get("troubleshooter_result")
    if result is None or result.case_id != selected_case_id:
        return

    _render_results(result)


def _render_results(result):
    """Render metrics and per-rule findings for a troubleshooting result."""
    findings = result.rule_findings

    st.markdown("### Analysis Results")

    issues = [
        finding
        for finding in findings
        if str(finding.status).lower() not in PASS_STATUSES
    ]

    col1, col2, col3 = st.columns(3)
    col1.metric("Rules Checked", len(findings))
    col2.metric("Issues Detected", len(issues))
    col3.metric("System Status", "ATTENTION" if issues else "HEALTHY")

    st.markdown("---")

    for finding in findings:
        _render_finding(finding)


def _render_finding(finding):
    """Render a single rule finding with status-appropriate styling."""
    status_lower = str(finding.status).lower()
    message = f"{finding.rule_id} | {finding.rule_name}\n\n{finding.finding}"

    if "fail" in status_lower or "critical" in status_lower:
        st.error(f"🚨 {message}")
    elif "warn" in status_lower:
        st.warning(f" {message}")
    else:
        st.success(f" {message}")