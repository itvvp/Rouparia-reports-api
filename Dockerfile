# trixie: o repositório da Microsoft abaixo é o debian/13
FROM python:3.12-slim-trixie

# Driver ODBC do SQL Server (o pyodbc precisa dele)
RUN apt-get update && apt-get install -y --no-install-recommends curl \
    && curl -fsSLO https://packages.microsoft.com/config/debian/13/packages-microsoft-prod.deb \
    && dpkg -i packages-microsoft-prod.deb \
    && rm packages-microsoft-prod.deb \
    && apt-get update \
    && ACCEPT_EULA=Y apt-get install -y --no-install-recommends msodbcsql17 \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# O nosso SQL Server só oferece TLS 1.0/1.1 e o OpenSSL 3 do Debian recusa-os por omissão.
# Só afeta a ligação à base de dados (a API não faz mais chamadas TLS de saída).
RUN printf '%s\n' \
    'openssl_conf = openssl_init' \
    '[openssl_init]' \
    'ssl_conf = ssl_sect' \
    '[ssl_sect]' \
    'system_default = system_default_sect' \
    '[system_default_sect]' \
    'MinProtocol = TLSv1' \
    'CipherString = DEFAULT@SECLEVEL=0' > /etc/ssl/openssl-legacy.cnf
ENV OPENSSL_CONF=/etc/ssl/openssl-legacy.cnf

WORKDIR /app
# `alembic` e `python -m app.cli` não põem /app no sys.path
ENV PYTHONPATH=/app PYTHONUNBUFFERED=1

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd --system --no-create-home --uid 10001 appuser
USER appuser

EXPOSE 8026

HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -fs http://localhost:8026/health || exit 1

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8026"]
