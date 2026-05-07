FROM python:3.11-slim

LABEL maintainer="AegisNDR"
LABEL description="Intelligent Network Detection & Response Platform"

WORKDIR /app

# System deps for Scapy / libpcap
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# App
COPY . .

# Create runtime directories
RUN mkdir -p logs data models

EXPOSE 8000

CMD ["python", "main.py", "--mock"]
