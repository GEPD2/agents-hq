FROM python:3.12-slim

RUN pip install --no-cache-dir fastapi uvicorn[standard] "starlette==0.46.2" "jinja2>=3.1.2,<3.2" python-multipart aiofiles pymysql

WORKDIR /app
COPY . /app/

ENV REPORTS_DIR=/agents-hq/reports
ENV AGENTS_BASE_DIR=/agents-hq

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8080"]
