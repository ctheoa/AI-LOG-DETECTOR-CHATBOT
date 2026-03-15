import streamlit as st
import os
import time
from openai import OpenAI  # Χρειάζεται pip install openai

# --- ΡΥΘΜΙΣΕΙΣ PATHS ---
WATCH_DIR = "/data_to_monitor"
MASTER_FILE_PATH = "/app/master_log.txt"

st.set_page_config(page_title="Log Aggregator", layout="wide", page_icon="🛡️")

# Initialize Session State για το Logging
if 'logging_active' not in st.session_state:
    st.session_state.logging_active = False

# Initialize Session State για το Chat History
if "messages" not in st.session_state:
    st.session_state.messages = []

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

# 2. SIDEBAR - ΕΛΕΓΧΟΣ & CONFIGURATION
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
   
    # ΚΟΥΜΠΙ 2: RESET (Clear All & Delete Master)
    if st.sidebar.button("🗑️ Clear All & Reset"):
        st.session_state.logging_active = False
        st.session_state.messages = [] # Καθαρίζει και το chat history στο reset
        if 'last_pos' in st.session_state:
            del st.session_state.last_pos
        if os.path.exists(MASTER_FILE_PATH):
            os.remove(MASTER_FILE_PATH)
        st.rerun()

# --- SECTION: AI CHATBOT (SIDEBAR) ---
st.sidebar.markdown("---")
st.sidebar.header("🤖 AI Log Analyst")

api_key = st.sidebar.text_input("Enter OpenAI API Key:", type="password")

if api_key:
    client = OpenAI(api_key=api_key)
   
    # Εμφάνιση ιστορικού μηνυμάτων στο sidebar
    for message in st.session_state.messages:
        with st.sidebar.chat_message(message["role"]):
            st.markdown(message["content"])

    # Chat Input
    if prompt := st.sidebar.chat_input("Ask about the logs..."):
        st.session_state.messages.append({"role": "user", "content": prompt})
        with st.sidebar.chat_message("user"):
            st.markdown(prompt)

        # Διάβασμα context από το Master Log (τελευταίες 3000 λέξεις)
        log_context = ""
        if os.path.exists(MASTER_FILE_PATH):
            with open(MASTER_FILE_PATH, "r", encoding="utf-8") as f:
                log_context = f.read()[-4000:]

        try:
            with st.sidebar.chat_message("assistant"):
                full_system_prompt = "You are a cybersecurity expert. Analyze the provided logs and answer briefly. If no logs exist, inform the user."
                full_user_prompt = f"LOG CONTEXT:\n{log_context}\n\nUSER QUESTION: {prompt}"
               
                stream = client.chat.completions.create(
                    model="gpt-3.5-turbo",
                    messages=[
                        {"role": "system", "content": full_system_prompt},
                        {"role": "user", "content": full_user_prompt},
                    ],
                    stream=False,
                )
                response_text = stream.choices[0].message.content
                st.markdown(response_text)
                st.session_state.messages.append({"role": "assistant", "content": response_text})
        except Exception as e:
            st.sidebar.error(f"AI Error: {e}")
else:
    st.sidebar.info("🔑 Enter an API Key to enable AI Analysis.")


# 3. ΚΥΡΙΟ LOOP ΚΑΤΑΓΡΑΦΗΣ (ΚΕΝΤΡΙΚΗ ΟΘΟΝΗ)
if st.session_state.logging_active and selected_files:
    st.info(f"🚀 Aggregating: {', '.join(selected_files)}")
   
    status_box = st.empty()
   
    if 'last_pos' not in st.session_state:
        st.session_state.last_pos = {f: 0 for f in selected_files}

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
       
        status_box.success(f"Syncing... Master Log Size: {os.path.getsize(MASTER_FILE_PATH)} bytes")
        time.sleep(2)
else:
    st.warning("⚠️ System Standby: Select files and Confirm.")
