FROM python:3.12-slim

RUN pip install --no-cache-dir fastapi uvicorn[standard] "starlette==0.46.2" "jinja2>=3.1.2,<3.2" python-multipart aiofiles pymysql

WORKDIR /app
COPY . /app/

ENV REPORTS_DIR=/agents-hq/reports
ENV AGENTS_BASE_DIR=/agents-hq

# Bind loopback only. The website container uses network_mode: host with no
# port mapping, so this bind is the real interface. 127.0.0.1 keeps the panel
# off the LAN; reach it from the host at http://127.0.0.1:8080 (or https via
# the website-tls proxy). proxy-headers lets the app trust X-Forwarded-Proto
# from that local proxy so the Secure cookie is set over HTTPS.
CMD ["uvicorn", "main:app", "--host", "127.0.0.1", "--port", "8080", "--proxy-headers", "--forwarded-allow-ips", "127.0.0.1"]
