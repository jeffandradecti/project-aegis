import streamlit as st
import pydeck as pdk
import sqlite3
import pandas as pd
import os
import time
from datetime import timedelta

# ==========================================
# PAGE CONFIGURATION & CSS
# ==========================================
st.set_page_config(layout="wide", page_title="Project Aegis | CTI Workbench")

st.markdown("""
    <style>
    .metric-container {
        background-color: rgba(14, 17, 23, 0.6);
        border: 1px solid #333;
        border-radius: 8px;
        padding: 15px;
        text-align: center;
        box-shadow: 0 0 15px rgba(0, 255, 65, 0.1);
    }
    .metric-value { font-size: 2rem; font-weight: bold; font-family: 'Courier New', monospace; }
    .metric-label { color: #888; font-size: 0.9rem; text-transform: uppercase; letter-spacing: 1px; }
    .triage-card {
        background: rgba(20, 24, 36, 0.8);
        padding: 15px;
        border-radius: 8px;
        border: 1px solid #333;
        margin-bottom: 15px;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        box-shadow: 0 4px 6px rgba(0,0,0,0.3);
    }
    .cmd-snippet {
        background-color: #0b0f19;
        color: #00FF41;
        padding: 6px 10px;
        font-size: 0.8rem;
        border-radius: 4px;
        display: block;
        margin-top: 10px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        font-family: 'Courier New', Courier, monospace;
        border-left: 2px solid #00FF41;
    }
    </style>
""", unsafe_allow_html=True)


# ==========================================
# DATA & STATE ENGINE
# ==========================================
@st.cache_data
def load_and_score_data():
    db_path = os.path.join(os.path.dirname(__file__), '..', 'data', 'aegis_intel.sqlite')
    if not os.path.exists(db_path):
        st.error(f"Database not found at {db_path}")
        return pd.DataFrame(), pd.DataFrame()

    conn = sqlite3.connect(db_path)

    # 1. Load Sessions & Commands
    query = """
            SELECT s.session_id, \
                   s.ip, \
                   s.start_time, \
                   s.src_lat, \
                   s.src_lon, \
                   s.dst_lat, \
                   s.dst_lon, \
                   s.src_country, \
                   s.src_city,
                   GROUP_CONCAT(c.command, ' | ') as all_commands,
                   COUNT(DISTINCT a.hash)         as malware_count
            FROM sessions s
                     LEFT JOIN commands c ON s.session_id = c.session_id
                     LEFT JOIN artifacts a ON s.session_id = a.session_id AND a.type = 'malware'
            WHERE s.src_lat IS NOT NULL
            GROUP BY s.session_id \
            """
    df = pd.read_sql_query(query, conn)
    df['start_time'] = pd.to_datetime(df['start_time'])
    df['all_commands'] = df['all_commands'].fillna('')

    # 2. Load Raw Artifacts for Forensics Tab
    artifacts_df = pd.read_sql_query("SELECT * FROM artifacts", conn)

    conn.close()

    # The Strict State Engine
    def evaluate_state(row):
        cmds = str(row['all_commands']).strip()
        file_count = int(row['malware_count'])

        if file_count > 0:
            return pd.Series(["FILE DROPPED", [255, 49, 49, 200], "#FF3131"])
        elif len(cmds) > 0:
            return pd.Series(["COMMAND", [255, 165, 0, 200], "#FFA500"])
        else:
            return pd.Series(["CONNECTION", [0, 255, 65, 200], "#00FF41"])

    df[['intent_label', 'arc_color', 'hex_color']] = df.apply(evaluate_state, axis=1)
    return df, artifacts_df


df_sessions, df_artifacts = load_and_score_data()

# ==========================================
# STATE MANAGEMENT & SIDEBAR
# ==========================================
if df_sessions.empty:
    st.warning("No data found. Please run the parser.")
    st.stop()

min_time = df_sessions['start_time'].min()
max_time = df_sessions['start_time'].max()

if 'current_time' not in st.session_state: st.session_state.current_time = min_time
if 'is_playing' not in st.session_state: st.session_state.is_playing = False

st.sidebar.title("🛡️ Project Aegis")
st.sidebar.markdown("### SOC Command Center")

playback_speed = st.sidebar.slider("Playback Speed (sec/frame)", 0.1, 2.0, 0.5)
window_size_hrs = st.sidebar.slider("Time Window (Hours)", 1, 12, 4)
step_minutes = st.sidebar.slider("Step Size (Minutes)", 10, 60, 30)

col1, col2, col3 = st.sidebar.columns(3)
if col1.button("▶ Play"): st.session_state.is_playing = True; st.rerun()
if col2.button("⏸ Pause"): st.session_state.is_playing = False; st.rerun()
if col3.button("🔄 Reset"): st.session_state.is_playing = False; st.session_state.current_time = min_time; st.rerun()

selected_time = st.sidebar.slider("Manual Timeline Scrub", min_value=min_time.to_pydatetime(),
                                  max_value=max_time.to_pydatetime(),
                                  value=st.session_state.current_time.to_pydatetime(), format="MM/DD HH:mm",
                                  disabled=st.session_state.is_playing)

if not st.session_state.is_playing:
    st.session_state.current_time = pd.to_datetime(selected_time)

start_window = st.session_state.current_time - timedelta(hours=window_size_hrs)
fs = df_sessions[
    (df_sessions['start_time'] >= start_window) & (df_sessions['start_time'] <= st.session_state.current_time)]

# ==========================================
# GLOBAL SEARCH FILTER
# ==========================================
st.markdown("### 🔎 Global Forensic Search")
search_query = st.text_input("Filter by IP, Command, City, or Country...", "")

if search_query:
    fs = fs[
        fs['ip'].str.contains(search_query, case=False, na=False) |
        fs['all_commands'].str.contains(search_query, case=False, na=False) |
        fs['src_city'].str.contains(search_query, case=False, na=False) |
        fs['src_country'].str.contains(search_query, case=False, na=False)
        ]

# ==========================================
# GLOBAL METRICS
# ==========================================
m1, m2, m3 = st.columns(3)
total_active = len(fs)
file_dropped_events = len(fs[fs['intent_label'] == 'FILE DROPPED'])
total_artifacts = fs['malware_count'].sum()

m1.markdown(
    f'<div class="metric-container"><div class="metric-value" style="color: #00F0FF;">{total_active}</div><div class="metric-label">Active Sessions</div></div>',
    unsafe_allow_html=True)
m2.markdown(
    f'<div class="metric-container"><div class="metric-value" style="color: #FF3131;">{file_dropped_events}</div><div class="metric-label">File Dropped Events</div></div>',
    unsafe_allow_html=True)
m3.markdown(
    f'<div class="metric-container"><div class="metric-value" style="color: #FF3131;">{total_artifacts}</div><div class="metric-label">Total Files Dropped</div></div>',
    unsafe_allow_html=True)

st.write("---")

# ==========================================
# FULL-WIDTH MAP
# ==========================================
if not fs.empty:
    arc_layer = pdk.Layer("ArcLayer", data=fs, get_source_position=["src_lon", "src_lat"],
                          get_target_position=["dst_lon", "dst_lat"], get_source_color="arc_color",
                          get_target_color=[255, 255, 255, 80], get_width=2, pickable=True, auto_highlight=True)
    source_layer = pdk.Layer("ScatterplotLayer", data=fs, get_position=["src_lon", "src_lat"],
                             get_fill_color="arc_color", get_radius=60000, pickable=True)
    view_state = pdk.ViewState(latitude=20.0, longitude=0.0, zoom=1.8, pitch=40)
    r = pdk.Deck(map_provider="carto", map_style="dark", layers=[arc_layer, source_layer],
                 initial_view_state=view_state, tooltip={"text": "Target IP: {ip}\nState: {intent_label}"}, height=500)
    st.pydeck_chart(r, use_container_width=True)
else:
    st.info("No geospatial data matching the current filter/timeframe.")

st.write("---")

# ==========================================
# WORKBENCH TABS (The "Everything" View)
# ==========================================
tab_triage, tab_analytics, tab_forensics, tab_godmode = st.tabs([
    "🚦 Live Triage Feed",
    "📈 Analytics & Attribution",
    "📁 File Forensics",
    "🗄️ Raw Data"
])

# --- TAB 1: TRIAGE FEED ---
with tab_triage:
    if fs.empty:
        st.info("No active sessions to triage.")
    else:
        sorted_fs = fs.sort_values(by=['malware_count', 'start_time'], ascending=[False, False]).head(24)
        cols = st.columns(3)
        for idx, row in sorted_fs.reset_index().iterrows():
            cmd_preview = row['all_commands'][:80] + '...' if len(row['all_commands']) > 80 else row['all_commands']
            if not cmd_preview: cmd_preview = "[No TTY Input]"
            malware_badge = f'<span style="float: right; background-color: #FF3131; color: #fff; padding: 2px 6px; border-radius: 4px; font-size: 0.75rem; font-weight: bold;">📦 {row["malware_count"]} Files</span>' if \
                row["malware_count"] > 0 else ""

            card_html = f"""
            <div class="triage-card" style="border-top: 4px solid {row['hex_color']};">
                <strong style="color: {row['hex_color']}; font-size: 0.85rem;">{row['intent_label']}</strong> {malware_badge}
                <div style="color: #E2E8F0; font-size: 1.2rem; margin-top: 6px; font-weight: bold;">{row['ip']}</div>
                <div style="color: #94A3B8; font-size: 0.85rem; margin-top: 2px;">📍 {row['src_city']}, {row['src_country']}</div>
                <div style="color: #64748B; font-size: 0.75rem; margin-top: 2px;">🕒 {row['start_time'].strftime('%Y-%m-%d %H:%M:%S')}</div>
                <code class="cmd-snippet">> {cmd_preview}</code>
            </div>
            """
            cols[idx % 3].markdown(card_html, unsafe_allow_html=True)

# --- TAB 2: ANALYTICS ---
with tab_analytics:
    st.markdown("### Top Attacking IPs")
    if not fs.empty:
        top_ips = fs['ip'].value_counts().head(10)
        st.bar_chart(top_ips)

        st.markdown("### Attack Timeline (Sessions over Time)")
        # Safeguard: Ensure start_time is explicitly datetime before setting index
        fs_time = fs.copy()
        fs_time['start_time'] = pd.to_datetime(fs_time['start_time'])
        timeline_data = fs_time.set_index('start_time').resample('H').size()
        st.line_chart(timeline_data)
    else:
        st.info("Not enough data for analytics.")

# --- TAB 3: FILE FORENSICS ---
with tab_forensics:
    st.markdown("### Captured Payload Inventory")
    file_sessions = fs[fs['malware_count'] > 0]

    if file_sessions.empty:
        st.success("No files dropped during this time window.")
    else:
        active_session_ids = file_sessions['session_id'].tolist()
        active_artifacts = df_artifacts[df_artifacts['session_id'].isin(active_session_ids)]

        for _, art in active_artifacts.iterrows():
            # Safeguard: Handle potential NULLs in the database
            safe_filename = art.get('filename', 'Unknown_Binary')
            if pd.isna(safe_filename): safe_filename = 'Unknown_Binary'

            safe_size = art.get('size', 'Unknown')
            if pd.isna(safe_size): safe_size = 'Unknown'

            safe_hash = art.get('hash', 'Missing_Hash')

            with st.expander(f"📦 File: {safe_filename} | Size: {safe_size} bytes"):
                st.code(f"SHA256: {safe_hash}", language="markdown")
                st.markdown(f"**Associated Session ID:** `{art.get('session_id', 'Unknown')}`")
                if safe_hash != 'Missing_Hash':
                    st.link_button("🔍 Check Hash on VirusTotal", f"https://www.virustotal.com/gui/file/{safe_hash}")

# --- TAB 4: RAW DATA ---
with tab_godmode:
    st.markdown("### Raw Session Data")
    st.dataframe(fs.drop(columns=['arc_color', 'hex_color']), use_container_width=True)

    st.markdown("### Raw Command Stream")
    cmds_only = fs[fs['all_commands'] != ''][['start_time', 'ip', 'all_commands']].sort_values(by='start_time',
                                                                                               ascending=False)
    st.dataframe(cmds_only, use_container_width=True)

# ==========================================
# ANIMATION LOOP
# ==========================================
if st.session_state.is_playing:
    if st.session_state.current_time < max_time:
        time.sleep(playback_speed)
        st.session_state.current_time += timedelta(minutes=step_minutes)
        st.rerun()
    else:
        st.session_state.is_playing = False
        st.success("Time-Lapse Complete.")
        st.rerun()