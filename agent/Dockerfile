FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH=/app

WORKDIR /app

COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r /app/requirements.txt

COPY oracle_agent /app/oracle_agent
COPY oracle_ctf_playbook /app/oracle_ctf_playbook

ENTRYPOINT ["python", "-m", "oracle_agent.main"]
CMD ["run"]
