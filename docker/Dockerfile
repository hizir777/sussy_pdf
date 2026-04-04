# ====================================================
# Sussy PDF - İzole Analiz Ortamı (Zero Trust)
# Multi-stage build, least-privilege, rootless
# ====================================================

# --- Stage 1: Builder ---
FROM python:3.12-slim AS builder

WORKDIR /build

# Sistem bağımlılıkları (derleme için)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        gcc \
        libmagic1 \
        && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir --prefix=/install -r requirements.txt

# --- Stage 2: Release (Production) ---
FROM python:3.12-slim AS release

# Güvenlik: Root olmayan kullanıcı oluştur
RUN groupadd -r analyzer && \
    useradd -r -g analyzer -d /app -s /sbin/nologin analyzer

# Runtime bağımlılıkları (sadece gerekli olanlar)
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        libmagic1 \
        && rm -rf /var/lib/apt/lists/* \
        && apt-get purge -y --auto-remove

# Builder'dan sadece kurulu paketleri al
COPY --from=builder /install /usr/local

WORKDIR /app

# Uygulama kodunu kopyala
COPY src/ ./src/
COPY specs/ ./specs/
COPY dashboard/ ./dashboard/
COPY .env.example ./.env.example

# Yetkileri kısıtla
RUN mkdir -p /app/output /app/uploads /app/test_logs && \
    chown -R analyzer:analyzer /app && \
    chmod -R 550 /app/src /app/specs && \
    chmod -R 770 /app/output /app/uploads /app/test_logs

# Root'tan çık — least privilege prensibi
USER analyzer

# Sağlık kontrolü
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import sys; sys.exit(0)"

# Analiz portu
EXPOSE 8443

# Giriş noktası
ENTRYPOINT ["python", "-m", "src.main"]
CMD ["--help"]
