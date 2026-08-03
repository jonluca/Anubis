FROM python:3.14-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
            build-essential \
            libssl-dev \
            libffi-dev \
            python3-dev \
        && rm -rf /var/lib/apt/lists/*

WORKDIR /Anubis/
COPY . /Anubis/

RUN pip3 install .

ENTRYPOINT ["anubis"]
