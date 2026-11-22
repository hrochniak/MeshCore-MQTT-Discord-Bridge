# Lightweight Python 3.11 image
FROM python:3.11-slim

# Set working directory inside the container
WORKDIR /app

# Copy requirements first (better Docker cache utilisation)
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy package source code
COPY meshcore_bridge/ meshcore_bridge/
COPY subscriber.py .

# Run the bridge
CMD ["python", "-u", "subscriber.py"]
