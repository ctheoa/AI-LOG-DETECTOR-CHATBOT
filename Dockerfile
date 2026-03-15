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

# Remove old tar.gz if it still exists in the build context
RUN rm -f chroma_db_v2.tar.gz

RUN mkdir -p /data_to_monitor /app/chat_history

ENV ANONYMIZED_TELEMETRY=false
ENV CHROMA_TELEMETRY=false
ENV CHROMA_PATH=/app/chroma_db_v2

# Make entrypoint executable
RUN chmod +x /app/entrypoint.sh

EXPOSE 8501

# entrypoint.sh builds ChromaDB on first start (has access to runtime env vars)
# then launches Streamlit
CMD ["/app/entrypoint.sh"]
