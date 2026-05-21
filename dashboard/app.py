"""
dashboard/app.py — Streamlit dashboard for IAM scan results.

Loads the most recent JSON output from ./outputs/ and renders an
interactive findings explorer with severity filters, compliance mapping,
and a risk score chart.

Run:
    streamlit run dashboard/app.py
"""

import json
import os
import glob

import streamlit as st
import pandas as pd
import plotly.express as px

st.set_page_config(
    page_title="IAM Scanner Dashboard",
    page_icon="🔐",
    layout="wide",
    initial_sidebar_state="expanded",
)

st.markdown("""
<style>
    .main { background-color: #f4f6f8; }
    .audit-note { background:#eaf4fb; padding:0.8rem 1rem; border-radius:6px;
                  border-left:3px solid #2d7dd2; font-style:italic; color:#34495e;
                  font-size:0.88rem; margin-top:0.5rem; }
</style>
""", unsafe_allow_html=True)


def _load_latest_json(output_dir: str):
    pattern = os.path.join(output_dir, "iam_scan_*.json")
    files   = sorted(glob.glob(pattern), reverse=True)
    if not files:
        return None
    with open(files[0], encoding="utf-8") as fh:
        return json.load(fh)


OUTPUT_DIR = os.path.join(os.path.dirname(__file__), "..", "outputs")

st.sidebar.markdown("## 🔐 IAM Scanner")
st.sidebar.markdown("*SOX ITGC · NIST 800-53*")
st.sidebar.divider()

output_dir_input = st.sidebar.text_input("Output directory", value=OUTPUT_DIR)
data = _load_latest_json(output_dir_input)

if data is None:
    st.warning(
        "⚠️ No scan results found. Run the scanner first:\n\n"
        "```\npython main.py --profile default\n```"
    )
    st.stop()

findings  = data.get("findings", [])
scan_meta = data.get("scan_metadata", {})
summary   = data.get("summary", {})
df_all    = pd.DataFrame(findings) if findings else pd.DataFrame()

st.sidebar.subheader("Filters")
severity_filter = st.sidebar.multiselect(
    "Severity",
    options=["High", "Medium", "Low"],
    default=["High", "Medium", "Low"],
)
sox_filter = st.sidebar.multiselect(
    "SOX Domain",
    options=df_all["sox_domain"].unique().tolist() if not df_all.empty else [],
    default=df_all["sox_domain"].unique().tolist() if not df_all.empty else [],
)

if not df_all.empty:
    df = df_all[
        (df_all["severity"].isin(severity_filter)) &
        (df_all["sox_domain"].isin(sox_filter))
    ]
else:
    df = df_all

st.title("🔐 AWS IAM Misconfiguration Scanner")
st.caption(
    f"Account: **{scan_meta.get('account_id', '—')}** · "
    f"Scanned: **{scan_meta.get('scan_date', '—')}** · "
    f"Profile: `{scan_meta.get('profile', '—')}`"
)
st.divider()

c1, c2, c3, c4 = st.columns(4)
c1.metric("Total Findings",     summary.get("total",  0))
c2.metric("🔴 High Severity",  summary.get("high",   0))
c3.metric("🟠 Medium Severity", summary.get("medium", 0))
c4.metric("🟢 Low Severity",   summary.get("low",    0))

st.divider()

col_pie, col_bar = st.columns(2)

with col_pie:
    st.subheader("Severity Distribution")
    if not df_all.empty:
        sev_counts = df_all["severity"].value_counts().reset_index()
        sev_counts.columns = ["Severity", "Count"]
        fig_pie = px.pie(
            sev_counts, values="Count", names="Severity",
            color="Severity",
            color_discrete_map={"High": "#c0392b", "Medium": "#e67e22", "Low": "#27ae60"},
            hole=0.45,
        )
        fig_pie.update_traces(textposition="outside", textinfo="label+percent")
        fig_pie.update_layout(showlegend=False, margin=dict(t=20, b=20))
        st.