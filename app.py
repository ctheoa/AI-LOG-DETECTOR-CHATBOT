import streamlit as st
import os
import time

# --- ΡΥΘΜΙΣΕΙΣ ---
# Αυτό το path είναι ΜΕΣΑ στο Docker. Εκεί θα εμφανιστούν τα logs του εξεταστή.
WATCH_DIR = "/data_to_monitor"
# Το αρχείο όπου θα συγκεντρώνονται όλα τα δεδομένα.
MASTER_FILE_PATH = "/app/master_log.txt"

st.set_page_config(page_title="System Log Aggregator", layout="wide")

st.title("🛡️ Live System Monitor")
st.sidebar.header("🔍 Ρυθμίσεις Παρακολούθησης")

# 1. ΛΕΙΤΟΥΡΓΙΑ ΑΝΙΧΝΕΥΣΗΣ (os.walk)
# Ψάχνουμε όλα τα αρχεία στον φάκελο που μας έδωσε ο εξεταστής.
files = []
if os.path.exists(WATCH_DIR):
    for root, dirs, filenames in os.walk(WATCH_DIR):
        for filename in filenames:
            # Παίρνουμε το σχετικό μονοπάτι (π.χ. apache2/access.log)
            rel_path = os.path.relpath(os.path.join(root, filename), WATCH_DIR)
            files.append(rel_path)

# 2. GUI: ΕΠΙΛΟΓΗ ΑΡΧΕΙΩΝ
if not files:
    st.error(f"Δεν βρέθηκαν αρχεία στο {WATCH_DIR}. Σιγουρευτείτε ότι το Volume Mount έγινε σωστά.")
else:
    # Ο εξεταστής διαλέγει ποια logs τον ενδιαφέρουν από τη λίστα.
    selected_files = st.sidebar.multiselect(
        "Επιλέξτε αρχεία για Live ανάγνωση:",
        options=files,
        default=files[:2] # Προεπιλογή τα πρώτα 2 αρχεία
    )
   
    # Επιλογή ταχύτητας ανανέωσης
    refresh_rate = st.sidebar.slider("Ρυθμός ανανέωσης (δευτερόλεπτα):", 1, 5, 1)

    # 3. ΚΥΡΙΟ LOOP ΣΥΛΛΟΓΗΣ (Aggregation)
    if selected_files:
        placeholder = st.empty()
       
        while True:
            combined_data = ""
           
            # Ανοίγουμε το Master αρχείο για εγγραφή ("w")
            with open(MASTER_FILE_PATH, "w", encoding="utf-8") as master:
                for f_name in selected_files:
                    full_path = os.path.join(WATCH_DIR, f_name)
                   
                    try:
                        # Διαβάζουμε το αρχείο του συστήματος (π.χ. syslog)
                        with open(full_path, "r", encoding="utf-8", errors="ignore") as f:
                            content = f.read()
                           
                            # Φτιάχνουμε ένα κεφαλίδιο για να ξέρουμε από πού ήρθε το log
                            header = f"\n>>> SOURCE: {f_name} | TIME: {time.strftime('%H:%M:%S')} <<<\n"
                           
                            # Γράφουμε στο Master αρχείο και στην οθόνη
                            master.write(header + content + "\n")
                            combined_data += header + content + "\n"
                    except Exception as e:
                        combined_data += f"\n[!] Σφάλμα πρόσβασης στο {f_name}: {e}\n"

            # Εμφάνιση στο Web UI
            with placeholder.container():
                st.code(combined_data, language="text")
                st.info(f"Το Master Log ενημερώθηκε: {MASTER_FILE_PATH}")

            time.sleep(refresh_rate)
