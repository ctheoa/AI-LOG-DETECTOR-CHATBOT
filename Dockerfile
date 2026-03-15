FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

# Αποσυμπίεση ChromaDB και διαγραφή του .tar.gz για να μην πιάνει χώρο
RUN tar -xzf chroma_db_v2.tar.gz && rm chroma_db_v2.tar.gz

RUN mkdir -p /data_to_monitor /app/chat_history

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
