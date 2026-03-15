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

# Build the ChromaDB collection from scratch at image build time.
# This guarantees the schema is always compatible with the installed
# ChromaDB version — no more "no such column" errors after upgrades.
# The OPENAI_API_KEY must be passed at build time:
#   docker compose build --build-arg OPENAI_API_KEY=sk-...
ARG OPENAI_API_KEY
ENV OPENAI_API_KEY=${OPENAI_API_KEY}
ENV CHROMA_PATH=/app/chroma_db_v2
ENV ANONYMIZED_TELEMETRY=false
ENV CHROMA_TELEMETRY=false

RUN python build_chroma.py

RUN mkdir -p /data_to_monitor /app/chat_history

EXPOSE 8501

CMD ["streamlit", "run", "app.py", "--server.port=8501", "--server.address=0.0.0.0"]
