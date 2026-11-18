FROM python:3.11-slim

# Install git and build tools (needed by tree-sitter-languages and GitPython)
RUN apt-get update && apt-get install -y --no-install-recommends \
    git gcc g++ make && \
    rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements and install dependencies (CPU-only torch)
COPY requirements.txt .
RUN pip install --no-cache-dir --upgrade pip && \
    pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu && \
    pip install --no-cache-dir -r requirements.txt

# Copy the entire vulnexplain project
COPY . .

# Expose the port Railway will assign
EXPOSE 8000

# Start the backend
CMD uvicorn backend.main:app --host 0.0.0.0 --port ${PORT:-8000}
