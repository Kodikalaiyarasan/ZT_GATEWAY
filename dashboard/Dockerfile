FROM python:3.12-slim

WORKDIR /app

RUN pip install --no-cache-dir --default-timeout=100 --retries=5 \
    fastapi==0.111.0 \
    uvicorn==0.30.1 \
    psycopg2-binary==2.9.9 \
    redis==5.0.4 \
    python-multipart==0.0.9 \
    requests==2.32.3

COPY main.py .

EXPOSE 9000
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "9000"]
