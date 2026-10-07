FROM alpine:3.18.2

LABEL org.opencontainers.image.authors="ProjectDiscovery"
LABEL org.opencontainers.image.description="Quickly discover exposed hosts on the internet using multiple search engines."
LABEL org.opencontainers.image.licenses="MIT"
LABEL org.opencontainers.image.title="uncover"
LABEL org.opencontainers.image.url="https://github.com/projectdiscovery/uncover"

RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates

ARG TARGETPLATFORM
COPY $TARGETPLATFORM/uncover /usr/local/bin/

ENTRYPOINT ["uncover"]
