# Χρήση επίσημης Python εικόνας
FROM python:3.9-slim

# Ορισμός φακέλου εργασίας
WORKDIR /app

# Εγκατάσταση απαραίτητων εργαλείων συστήματος (για σταθερότητα)
RUN apt-get update && apt-get install -y \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

# Αντιγραφή του requirements και εγκατάσταση
# ΠΡΟΣΟΧΗ: Βεβαιώσου ότι στο requirements.txt έχεις streamlit>=1.33.0
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Αντιγραφή όλου του κώδικα (app.py κλπ)
COPY . .

# Δημιουργία του φακέλου όπου θα γίνουν mount τα logs του καθηγητή
RUN mkdir -p /data_to_monitor

# Έκθεση της θύρας του Streamlit
EXPOSE 8501

# Εντολή εκτέλεσης με ρυθμίσεις για αποφυγή προβλημάτων σύνδεσης
CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
