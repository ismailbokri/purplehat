# VulnShop - intentionally vulnerable target
# Older base image on purpose (adds "outdated components" findings).
FROM python:3.9-slim

LABEL org.opencontainers.image.title="VulnShop" \
      org.opencontainers.image.description="Intentionally vulnerable e-commerce target for AUTHORIZED security testing only" \
      org.opencontainers.image.licenses="MIT"

ENV PYTHONUNBUFFERED=1 \
    FLASK_ENV=development \
    FLASK_DEBUG=1

WORKDIR /app

# ping/iputils are needed by the (vulnerable) network-tools feature.
RUN apt-get update \
    && apt-get install -y --no-install-recommends iputils-ping curl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 5000

# debug=True (Werkzeug interactive debugger) is set inside app.py.
CMD ["python", "app.py"]
