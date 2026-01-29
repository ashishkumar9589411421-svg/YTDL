# Use python 3.10 slim version
FROM python:3.10-slim

# 1. Install System Dependencies
# We install 'curl' to get a newer Node.js version, 'ffmpeg' for video, and 'git' for pip
RUN apt-get update && \
    apt-get install -y curl ffmpeg git && \
    curl -fsSL https://deb.nodesource.com/setup_18.x | bash - && \
    apt-get install -y nodejs && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# 2. Setup App
WORKDIR /app

# 3. Install Python Deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# 4. Copy Code
COPY . .

# 5. Create Folders
RUN mkdir -p downloads uploads

# 6. Run
EXPOSE 5000
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
