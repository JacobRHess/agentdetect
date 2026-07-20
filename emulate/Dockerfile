# The disposable host the emulation agent operates inside. Everything here is
# synthetic honeypot data - fake cloud keys, a decoy SSH key, a planted token -
# so the agent has realistic targets to find without anything real being at risk.
FROM debian:stable-slim

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      curl wget iproute2 procps findutils grep sudo ca-certificates \
 && rm -rf /var/lib/apt/lists/*

RUN useradd -m -s /bin/bash svc-deploy

COPY honeypot/ /seed/

RUN mkdir -p /home/svc-deploy/.aws /home/svc-deploy/.ssh /opt/app/data \
 && cp /seed/aws_credentials /home/svc-deploy/.aws/credentials \
 && cp /seed/id_rsa          /home/svc-deploy/.ssh/id_rsa \
 && cp /seed/app_config.yaml /opt/app/config.yaml \
 && cp /seed/deploy.env      /opt/app/.env \
 && chmod 600 /home/svc-deploy/.ssh/id_rsa /home/svc-deploy/.aws/credentials \
 && chown -R svc-deploy:svc-deploy /home/svc-deploy /opt/app

WORKDIR /home/svc-deploy
