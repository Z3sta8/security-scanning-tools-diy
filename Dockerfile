FROM python:3.11-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    bash \
    lsof \
    procps \
    net-tools \
    iproute2 \
    findutils \
    coreutils \
    sudo \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application files
COPY security_monitor.py .
COPY web_dashboard.py .
COPY config.json .

# Copy security scanning scripts
COPY *.sh ./
RUN chmod +x *.sh

# Create directories for logs and data
RUN mkdir -p /var/log/security_monitor \
    /var/lib/security_monitor \
    /root/.security

# Create volumes
VOLUME ["/var/log/security_monitor", "/var/lib/security_monitor"]

# Expose web dashboard port
EXPOSE 8080

# Create entrypoint script
RUN echo '#!/bin/bash\n\
set -e\n\
\n\
# Start web dashboard in background\n\
python3 /app/web_dashboard.py &\n\
\n\
# Start security monitor\n\
exec python3 /app/security_monitor.py\n\
' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
