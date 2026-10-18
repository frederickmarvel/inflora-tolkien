# syntax=docker/dockerfile:1.6
FROM golang:1.25-alpine AS builder
WORKDIR /src/inflora-tolkien
COPY inflora-shared /src/inflora-shared
COPY inflora-tolkien/go.mod inflora-tolkien/go.sum ./
RUN go mod download
COPY inflora-tolkien .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/inflora-tolkien ./cmd/server

FROM alpine:3.21
RUN apk add --no-cache ca-certificates wget && addgroup -S inflora && adduser -S -G inflora inflora
COPY --from=builder /out/inflora-tolkien /usr/local/bin/inflora-tolkien
USER inflora:inflora
ENTRYPOINT ["/usr/local/bin/inflora-tolkien"]
EXPOSE 8080
