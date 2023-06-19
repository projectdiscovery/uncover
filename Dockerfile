# Base
FROM golang:1.20.5-alpine AS builder
RUN apk add --no-cache git build-base
WORKDIR /app
COPY . /app
RUN go mod download
RUN go build -o ./cmd/uncover ./cmd/uncover

# Release
FROM alpine:3.18.2
RUN apk -U upgrade --no-cache \
    && apk add --no-cache bind-tools ca-certificates
COPY --from=builder /app/cmd/uncover/uncover /usr/local/bin/

ENTRYPOINT ["uncover"]