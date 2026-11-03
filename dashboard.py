"""Painel Streamlit do AgentWatch.

    streamlit run dashboard.py

Le o SQLite local por padrao. Para usar a API: defina AGENTWATCH_API_URL
(e AGENTWATCH_API_KEY, se a API exigir chave).
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

import pandas as pd  # noqa: E402
import streamlit as st  # noqa: E402

from agentwatch.datasource import get_source  # noqa: E402
from agentwatch.queries import SEVERITY_ORDER  # noqa: E402

ICON = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🔵"}
LEVELS = list(reversed(SEVERITY_ORDER))  # LOW -> CRITICAL


def tag(severity):
    return f"{ICON.get(severity, '')} {severity}" if severity else "-"


def short_ts(ts):
    return (ts or "").replace("T", " ")[:19]


st.set_page_config(page_title="AgentWatch", page_icon="🛡️", layout="wide")
st.title("🛡️ AgentWatch")

source = get_source()
try:
    stats = source.stats()
    sessions = source.sessions()
except Exception as exc:  # noqa: BLE001
    st.error(f"Não foi possível carregar os dados ({source.label}: {source.where}): {exc}")
    st.stop()

st.caption(f"Fonte: {source.label} · {source.where}")

if stats["events"] == 0:
    st.info("Nenhum evento registrado ainda. Ative o hook do Claude Code ou gere dados de "
            "demonstração com `python -m agentwatch.seed --db /tmp/demo.db`.")
    st.stop()

# ------------------------------------------------------------------ filtros
with st.sidebar:
    st.header("Filtros (aba Alertas)")
    min_severity = st.select_slider("Severidade mínima", options=LEVELS, value="LOW")
    rules = ["(todas)"] + list(stats["alerts_by_rule"])
    rule = st.selectbox("Regra", rules)
    if st.button("Atualizar dados"):
        st.rerun()

# ---------------------------------------------------------------------- KPIs
sev = stats["alerts_by_severity"]
c1, c2, c3, c4 = st.columns(4)
c1.metric("Eventos", stats["events"])
c2.metric("Alertas", stats["alerts"])
c3.metric("Sessões", stats["sessions"])
c4.metric("Alertas HIGH + CRITICAL", sev["HIGH"] + sev["CRITICAL"])

tab_overview, tab_alerts, tab_sessions = st.tabs(["Visão geral", "Alertas", "Sessões"])

# ---------------------------------------------------------------- visão geral
with tab_overview:
    left, mid, right = st.columns(3)
    with left:
        st.subheader("Alertas por severidade")
        df = pd.DataFrame({"severidade": SEVERITY_ORDER,
                           "alertas": [sev[s] for s in SEVERITY_ORDER]})
        st.bar_chart(df, x="severidade", y="alertas", sort=False)
    with mid:
        st.subheader("Alertas por regra")
        if stats["alerts_by_rule"]:
            df = pd.DataFrame({"regra": list(stats["alerts_by_rule"]),
                               "alertas": list(stats["alerts_by_rule"].values())})
            st.bar_chart(df, x="regra", y="alertas", sort="-alertas")
        else:
            st.caption("Nenhum alerta.")
    with right:
        st.subheader("Eventos por ferramenta")
        df = pd.DataFrame({"ferramenta": list(stats["events_by_tool"]),
                           "eventos": list(stats["events_by_tool"].values())})
        st.bar_chart(df, x="ferramenta", y="eventos", sort="-eventos")

    st.subheader("Atividade por dia")
    daily = pd.DataFrame(stats["daily"]).set_index("day")[["events", "alerts"]]
    daily.columns = ["eventos", "alertas"]
    st.line_chart(daily)

# --------------------------------------------------------------------- alertas
with tab_alerts:
    alerts = source.alerts(limit=500, min_severity=min_severity,
                           rule_id=None if rule == "(todas)" else rule)
    st.write(f"**{len(alerts)}** alertas (severidade ≥ {min_severity}"
             f"{'' if rule == '(todas)' else f', regra {rule}'}), mais recentes primeiro.")
    if alerts:
        table = pd.DataFrame([{
            "Severidade": tag(a["severity"]),
            "Quando (UTC)": short_ts(a["ts"]),
            "Regra": a["rule_id"],
            "Ação": a["detail"],
            "Motivo": a["message"],
            "Sessão": a["session_id"],
        } for a in alerts])
        st.dataframe(table, hide_index=True, use_container_width=True)
    else:
        st.success("Nenhum alerta com esses filtros.")

# -------------------------------------------------------------------- sessões
with tab_sessions:
    table = pd.DataFrame([{
        "Sessão": s["session_id"] or "(sem id)",
        "Início (UTC)": short_ts(s["first_ts"]),
        "Fim (UTC)": short_ts(s["last_ts"]),
        "Eventos": s["events"],
        "Alertas": s["alerts"],
        "Pior severidade": tag(s["max_severity"]),
    } for s in sessions])
    st.dataframe(table, hide_index=True, use_container_width=True)

    named = [s for s in sessions if s["session_id"]]
    if named:
        chosen = st.selectbox(
            "Linha do tempo da sessão", [s["session_id"] for s in named],
            format_func=lambda sid: next(
                f"{sid}  ·  {s['events']} eventos, {s['alerts']} alertas" for s in named
                if s["session_id"] == sid))
        timeline = source.timeline(chosen)
        st.dataframe(pd.DataFrame([{
            "Hora (UTC)": short_ts(e["ts"]),
            "Ferramenta": e["tool_name"],
            "Ação": e["command"] or e["file_path"] or e["url"] or "",
            "Alertas": " · ".join(f"{tag(a['severity'])} {a['rule_id']}" for a in e["alerts"]),
        } for e in timeline]), hide_index=True, use_container_width=True)
