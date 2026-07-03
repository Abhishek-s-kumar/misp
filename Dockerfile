FROM python:3.11-slim

WORKDIR /app

# System deps
RUN apt-get update && apt-get install -y \
    git \
    ansible \
    yara \
    openssh-client \
    && rm -rf /var/lib/apt/lists/*

# Python deps
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy codebase
COPY . .

# Set pythonpath
ENV PYTHONPATH=/app
ENV LC_ALL=C.UTF-8
ENV LANG=C.UTF-8

# Init repository git if not already
RUN cd /app/repository && git init && git checkout -b main 2>/dev/null || true

EXPOSE 9640

CMD ["python", "api/server.py"]
RUN git config --system user.email "misp-pipeline@local" && \
    git config --system user.name "MISP Pipeline"
