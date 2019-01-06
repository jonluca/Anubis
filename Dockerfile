FROM python:3.7-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
            build-essential \
            libssl-dev \
            libffi-dev \
            python-dev \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /Anubis/
COPY . /Anubis/

RUN pip3 install .

ENTRYPOINT ["anubis"]
