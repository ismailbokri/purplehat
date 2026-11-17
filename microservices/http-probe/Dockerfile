FROM python:3.11-slim-bullseye

WORKDIR /app

COPY requirements.txt .
RUN pip install -r requirements.txt

COPY probe_runner.py .

ENTRYPOINT ["python", "probe_runner.py"]
