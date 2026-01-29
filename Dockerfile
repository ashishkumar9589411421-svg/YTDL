# Use a lightweight Python image
FROM python:3.10-slim

# Install FFmpeg (for merging video/audio) AND Node.js (for YouTube n-challenges)
RUN apt-get update && \
    apt-get install -y ffmpeg nodejs git && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy your app code
COPY . .

# Create necessary folders
RUN mkdir -p downloads uploads

# Expose the port
EXPOSE 5000

# Start the app
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "app:app"]
