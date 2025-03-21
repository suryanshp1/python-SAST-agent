# Dockerfile
FROM python:3.11-slim-buster

# Install system dependencies
RUN apt-get update && \
    apt-get install -y git && \
    apt-get clean && \
    pip3 install --upgrade pip && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy requirements first to leverage Docker cache
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app.py .
COPY frontend.py .
COPY utils.py .

# Expose ports
EXPOSE 8000
EXPOSE 7860

CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "8000", "--reload"]