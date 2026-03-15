import streamlit as st
import os
import time

# --- ΡΥΘΜΙΣΕΙΣ PATHS ---
WATCH_DIR = "/data_to_monitor"
MASTER_FILE_PATH = "/app/master_log.txt"

st.set_page_config(page_title="Log Aggregator", layout="wide", page_icon="🛡️")

# Initialize Session State
if 'logging_active' not in st.session_state:
    st.session_state.logging_active = False

st.title("🛡️ Secure Log Aggregation Engine")
st.markdown("---")

# 1. ΑΝΙΧΝΕΥΣΗ ΑΡΧΕΙΩΝ (Recursive)
files = []
if os.path.exists(WATCH_DIR):
    for root, dirs, filenames in os.walk(WATCH_DIR):
        for filename in filenames:
            rel_path = os.path.relpath(os.path.join(root, filename), WATCH_DIR)
            files.append(rel_path)
    files.sort()

# 2. SIDEBAR - ΕΛΕΓΧΟΣ
st.sidebar.header("🔍 Configuration")

if not files:
    st.sidebar.error("⚠️ No logs found in /data_to_monitor")
else:
    # Επιλογή αρχείων
    selected_files = st.sidebar.multiselect(
        "Select Files to Monitor:",
        options=files,
        default=None,
        disabled=st.session_state.logging_active
    )

    # ΚΟΥΜΠΙ 1: ΕΝΑΡΞΗ (Confirm)
    if not st.session_state.logging_active:
        if st.sidebar.button("✅ Confirm & Start", type="primary"):
            if selected_files:
                st.session_state.logging_active = True
                # Δημιουργία/Καθαρισμός του master log για τη νέα δοκιμή
                with open(MASTER_FILE_PATH, "w", encoding="utf-8") as f:
                    f.write(f"--- LOGGING START: {time.strftime('%Y-%m-%d %H:%M:%S')} ---\n")
                st.rerun()
            else:
                st.sidebar.warning("Please select files first.")
   
    # ΚΟΥΜΠΙ 2: RESET (Clear All)
    # Αυτό το κουμπί σταματάει τα πάντα, σβήνει το master και ξεκλειδώνει τις επιλογές
    if st.sidebar.button("🗑️ Clear All & Reset"):
        st.session_state.logging_active = False
        if 'last_pos' in st.session_state:
            del st.session_state.last_pos
        if os.path.exists(MASTER_FILE_PATH):
            os.remove(MASTER_FILE_PATH)
        st.rerun()

# 3. ΚΥΡΙΟ LOOP ΚΑΤΑΓΡΑΦΗΣ
if st.session_state.logging_active and selected_files:
    st.info(f"🚀 Aggregating: {', '.join(selected_files)}")
   
    status_box = st.empty()
   
    # Αρχικοποίηση θέσης pointer
    if 'last_pos' not in st.session_state:
        st.session_state.last_pos = {f: 0 for f in selected_files}

    # Το loop τρέχει όσο το logging_active είναι True
    while st.session_state.logging_active:
        with open(MASTER_FILE_PATH, "a", encoding="utf-8") as master:
            for f_name in selected_files:
                full_path = os.path.join(WATCH_DIR, f_name)
               
                if os.path.exists(full_path):
                    with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                        f.seek(st.session_state.last_pos.get(f_name, 0))
                        new_data = f.read()
                       
                        if new_data:
                            header = f"\n[SOURCE: {f_name} | {time.strftime('%H:%M:%S')}]\n"
                            master.write(header + new_data)
                            st.session_state.last_pos[f_name] = f.tell()
       
        status_box.success(f"Syncing... Master Log: {os.path.getsize(MASTER_FILE_PATH)} bytes")
        time.sleep(2)
else:
    st.warning("⚠️ System Standby: Select files and Confirm.")
