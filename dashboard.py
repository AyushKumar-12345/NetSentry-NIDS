import json
import os
import pandas as pd
import plotly.graph_objects as go
import streamlit as st

st.set_page_config(
    page_title="NetSentry SIEM Platform",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed"
)

# Clean, modern light theme styling
st.markdown("""
<style>
    @import url('https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@500;600;700;800&family=JetBrains+Mono:wght@500;600&display=swap');
    
    html, body, [class*="css"], .stApp {
        font-family: 'Plus Jakarta Sans', sans-serif !important;
        background-color: #f8fafc !important;
        color: #0f172a !important;
    }
    
    header[data-testid="stHeader"], footer, #MainMenu {
        display: none !important;
    }
    
    [data-testid="stSidebar"] {
        display: none !important;
    }

    .main .block-container {
        max-width: 1400px !important;
        padding: 2rem 2.5rem 3rem 2.5rem !important;
    }

    /* Metric Cards */
    div[data-testid="stMetric"] {
        background: #ffffff !important;
        border: 1px solid #e2e8f0 !important;
        border-radius: 16px !important;
        padding: 18px 22px !important;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02) !important;
    }
    div[data-testid="stMetricLabel"] p {
        font-size: 0.78rem !important;
        font-weight: 700 !important;
        text-transform: uppercase !important;
        letter-spacing: 0.05em !important;
        color: #64748b !important;
    }
    div[data-testid="stMetricValue"] div {
        font-size: 2.2rem !important;
        font-weight: 800 !important;
        color: #0f172a !important;
    }

    /* White content panels */
    .card-panel {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 16px;
        padding: 24px;
        box-shadow: 0 1px 3px rgba(0, 0, 0, 0.02);
        margin-bottom: 20px;
    }
    .card-heading {
        font-size: 1rem;
        font-weight: 800;
        color: #0f172a;
        margin-bottom: 16px;
        letter-spacing: -0.02em;
    }
</style>
""", unsafe_allow_html=True)

log_path = os.path.join("logs", "nids_alerts.json")

def load_data():
    if not os.path.exists(log_path) or os.stat(log_path).st_size == 0:
        return pd.DataFrame()
    records = []
    with open(log_path, "r", encoding="utf-8") as f:
        for line in f:
            if line.strip():
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    if not records:
        return pd.DataFrame()
    return pd.DataFrame(records)

df_raw = load_data()

# Header
head_col1, head_col2 = st.columns([4, 1])
with head_col1:
    st.title("🛡️ NetSentry SIEM Console")
    st.caption("Real-Time Autonomous Packet Telemetry & Network Intrusion Defense")
with head_col2:
    st.markdown("<div style='height: 12px;'></div>", unsafe_allow_html=True)
    st.success("● Engine Active")

if df_raw.empty:
    st.info("No security events logged yet. Start capturing network traffic via `python nids.py`.")
else:
    total_alerts = len(df_raw)
    crit_count = len(df_raw[df_raw["severity"] == "CRITICAL"])
    warn_count = len(df_raw[df_raw["severity"] == "WARNING"])
    unique_sources = len(set(
        str(d.get("source_ip") or d.get("responder_ip") or d.get("ip"))
        for d in df_raw["details"] if isinstance(d, dict)
    ))

    # Metric KPI Cards
    m1, m2, m3, m4 = st.columns(4)
    m1.metric("Total Interceptions", total_alerts, "100% Ingested")
    m2.metric("Critical Threats", crit_count, "Active Floods / MitM", delta_color="inverse")
    m3.metric("Policy Warnings", warn_count, "Rogue DNS / Scans", delta_color="off")
    m4.metric("Flagged Nodes", unique_sources, "Offending Hosts")

    st.markdown("<div style='height: 20px;'></div>", unsafe_allow_html=True)

    # Filter selector
    filter_choice = st.pills(
        "Filter Stream",
        options=["All Events", "Critical Only", "Warnings Only"],
        default="All Events",
        label_visibility="collapsed"
    )

    if filter_choice == "Critical Only":
        df = df_raw[df_raw["severity"] == "CRITICAL"].copy()
    elif filter_choice == "Warnings Only":
        df = df_raw[df_raw["severity"] == "WARNING"].copy()
    else:
        df = df_raw.copy()

    # Visual Analytics Split
    c_left, c_right = st.columns([1.2, 0.8])

    with c_left:
        st.markdown('<div class="card-panel"><div class="card-heading">📊 Detected Threat Signatures</div>', unsafe_allow_html=True)
        counts = df["alert_type"].value_counts()
        total_scope = len(df) if len(df) > 0 else 1

        for vec, cnt in counts.items():
            pct = round((cnt / total_scope) * 100, 1)
            row_l, row_r = st.columns([3, 1])
            with row_l:
                st.markdown(f"**`{vec}`**")
            with row_r:
                st.markdown(f"<div style='text-align:right; font-weight:700;'>{cnt} ({pct}%)</div>", unsafe_allow_html=True)
            st.progress(cnt / total_scope)
            st.markdown("<div style='height: 6px;'></div>", unsafe_allow_html=True)
        st.markdown('</div>', unsafe_allow_html=True)

    with c_right:
        st.markdown('<div class="card-panel"><div class="card-heading">🎯 Severity Breakdown</div>', unsafe_allow_html=True)
        sev_counts = df["severity"].value_counts()
        color_map = {"CRITICAL": "#ef4444", "WARNING": "#f59e0b"}

        labels = list(sev_counts.index)
        values = list(sev_counts.values)
        colors = [color_map.get(s, "#0284c7") for s in labels]

        fig = go.Figure(data=[go.Pie(
            labels=labels,
            values=values,
            hole=0.72,
            marker=dict(colors=colors, line=dict(color="#ffffff", width=2)),
            textinfo='percent',
            textfont=dict(size=13, family="Plus Jakarta Sans", color="#ffffff"),
            hoverinfo='label+value'
        )])

        fig.add_annotation(
            text=f"<b style='font-size:24px; color:#0f172a;'>{len(df)}</b><br><span style='font-size:11px; color:#64748b;'>TOTAL</span>",
            x=0.5, y=0.5,
            showarrow=False,
            font=dict(family="Plus Jakarta Sans")
        )

        fig.update_layout(
            paper_bgcolor="#ffffff",
            plot_bgcolor="#ffffff",
            margin=dict(l=0, r=0, t=10, b=10),
            height=200,
            showlegend=True,
            legend=dict(
                orientation="h",
                yanchor="bottom",
                y=-0.25,
                xanchor="center",
                x=0.5,
                font=dict(size=12, family="Plus Jakarta Sans", color="#475569")
            )
        )
        st.plotly_chart(fig, use_container_width=True, config={"displayModeBar": False})
        st.markdown('</div>', unsafe_allow_html=True)

    # Interactive Table
    st.markdown("<h3 style='font-size:1.05rem; font-weight:800; color:#0f172a; margin-top:10px;'>⚡ Live Security Incident Audit Feed</h3>", unsafe_allow_html=True)

    display_df = df[["readable_time", "alert_type", "severity", "details"]].copy()
    display_df["details"] = display_df["details"].apply(lambda d: json.dumps(d) if isinstance(d, dict) else str(d))
    display_df = display_df.rename(columns={
        "readable_time": "Timestamp",
        "alert_type": "Threat Vector",
        "severity": "Severity",
        "details": "Payload Artifacts"
    })

    st.dataframe(
        display_df,
        use_container_width=True,
        hide_index=True,
        column_config={
            "Timestamp": st.column_config.TextColumn(width="medium"),
            "Threat Vector": st.column_config.TextColumn(width="medium"),
            "Severity": st.column_config.TextColumn(width="small"),
            "Payload Artifacts": st.column_config.TextColumn(width="large")
        }
    )