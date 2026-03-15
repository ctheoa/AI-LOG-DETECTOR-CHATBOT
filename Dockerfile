FROM python:3.9-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    build-essential \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Install numpy FIRST before chromadb to avoid np.float_ crash
RUN pip install --no-cache-dir "numpy<2.0"

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN tar -xzf chroma_db_v2.tar.gz && rm chroma_db_v2.tar.gz
RUN echo "=== ChromaDB contents ===" && ls -la /app/chroma_db_v2/

RUN mkdir -p /data_to_monitor /app/chat_history

ENV ANONYMIZED_TELEMETRY=false
ENV CHROMA_TELEMETRY=false

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
