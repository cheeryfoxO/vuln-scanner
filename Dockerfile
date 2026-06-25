FROM python:3.13-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    dnsutils \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements and install Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy scanner code
COPY scanner/ ./scanner/
COPY tests/ ./tests/
COPY README.md .

# Expose web UI port
EXPOSE 8085

# Default command: show help
ENTRYPOINT ["python", "-m", "scanner"]
CMD ["--help"]
