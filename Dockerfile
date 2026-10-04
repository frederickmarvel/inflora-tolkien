# syntax=docker/dockerfile:1.6
FROM golang:1.24-alpine AS builder
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/inflora-tolkien ./cmd/server

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=builder /out/inflora-tolkien /usr/local/bin/inflora-tolkien
USER nonroot:nonroot
ENTRYPOINT ["/usr/local/bin/inflora-tolkien"]
EXPOSE 8080
