FROM python:3.9-slim

WORKDIR /code

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV TZ=UTC

RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    postgresql-client \
    libssl-dev \
    netcat-openbsd \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /code/
RUN pip install --no-cache-dir -r requirements.txt

COPY . /code/

RUN chmod +x /code/start_docker.sh
RUN chmod +x /code/start_postgres.sh

CMD ["/code/start_docker.sh", "web"]