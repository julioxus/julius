FROM python:3.12-slim

WORKDIR /app

# Install system deps for psycopg2
RUN apt-get update && apt-get install -y --no-install-recommends libpq-dev gcc && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
COPY bounty_intel/ bounty_intel/

RUN pip install --no-cache-dir .

EXPOSE 8080

CMD ["uvicorn", "bounty_intel.web.app:app", "--host", "0.0.0.0", "--port", "8080"]
