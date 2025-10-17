"""Minimal Streamlit dashboard for AI alerts."""
from __future__ import annotations

import json
from pathlib import Path

import pandas as pd
import streamlit as st

DATA_DIR = Path("/data/alerts")

st.set_page_config(page_title="Trusted AI SOC Lite", layout="wide")
st.title("Trusted AI SOC Lite – AI Alerts")

alerts_file = DATA_DIR / "alerts.jsonl"
if alerts_file.exists():
    rows = [json.loads(line) for line in alerts_file.read_text().splitlines() if line.strip()]
    if rows:
        df = pd.json_normalize(rows, sep=".")
        st.dataframe(df.tail(200))
    else:
        st.info("No alerts recorded yet.")
else:
    st.warning("alerts.jsonl not found. Ensure soc-ai is running and writing alerts.")
