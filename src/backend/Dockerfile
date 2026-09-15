FROM python:3.11-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    DATABASE_URL=sqlite:////app/data/elevatex.db

WORKDIR /app

COPY src/backend/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY src/backend/app ./app
COPY src/intelligence ./intelligence
COPY src/data /data

RUN mkdir -p /app/data

EXPOSE 8000

CMD ["sh", "-c", "python -m app.db.seed && uvicorn app.main:app --host 0.0.0.0 --port 8000"]

# For persistence across container restarts, mount a volume at /app/data and
# keep DATABASE_URL pointed at a file inside that mount (default shown above).
