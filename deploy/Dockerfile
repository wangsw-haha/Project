FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    && rm -rf /var/lib/apt/lists/*

# Create app directory
WORKDIR /app

# Copy requirements first for better caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create logs directory
RUN mkdir -p logs

# Create non-root user for security
RUN useradd -m -u 1000 honeypot && chown -R honeypot:honeypot /app
USER honeypot

# Expose ports
EXPOSE 22 23 80 443 502

# Set environment variables
ENV PYTHONPATH=/app/src
ENV OPENAI_API_KEY=""

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=60s --retries=3 \
    CMD python -c "import socket; s=socket.socket(); s.connect(('localhost', 80)); s.close()" || exit 1

# Run the honeypot
CMD ["python", "src/main.py", "-c", "config/honeypot.yaml"]