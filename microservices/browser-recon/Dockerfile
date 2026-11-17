FROM python:3.11-slim

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

# Install Chromium system dependencies manually.
# --with-deps fails on python:3.11-slim (Debian Bookworm) because it tries to
# install ttf-unifont (replaced by fonts-unifont) and ttf-ubuntu-font-family
# (Ubuntu-only package, absent from Debian repos).
RUN apt-get update && apt-get install -y --no-install-recommends \
    # Core Chromium libs
    libnss3 \
    libnspr4 \
    libatk1.0-0 \
    libatk-bridge2.0-0 \
    libcups2 \
    libdrm2 \
    libxkbcommon0 \
    libxcomposite1 \
    libxdamage1 \
    libxfixes3 \
    libxrandr2 \
    libgbm1 \
    libasound2 \
    libpango-1.0-0 \
    libpangocairo-1.0-0 \
    libcairo2 \
    libgtk-3-0 \
    # Fonts (Debian-correct names)
    fonts-liberation \
    fonts-unifont \
    && rm -rf /var/lib/apt/lists/*

# Download Chromium binary only (deps already satisfied above)
RUN playwright install chromium

COPY browser_recon_runner.py .
COPY capture_runner.py .

ENTRYPOINT ["python", "browser_recon_runner.py"]