FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY dba_agent ./dba_agent
COPY settings.json policy.json ./
COPY tasks ./tasks

ENTRYPOINT ["python", "-m", "dba_agent.main"]
