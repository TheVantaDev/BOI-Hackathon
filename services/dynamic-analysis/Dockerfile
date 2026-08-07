FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
# gcc + python3-dev are required to build frida's native extension
RUN apt-get update && \
    apt-get install -y \
    adb \
    tcpdump \
    curl \
    gcc \
    python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source
COPY . .

EXPOSE 8011

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8011"]
