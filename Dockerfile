# Build
FROM golang:1.22-alpine AS builder
WORKDIR /app
COPY . .
RUN go mod download && go build -o hostdiff ./cmd/server

# Run
FROM alpine:latest
RUN apk add --no-cache ca-certificates
WORKDIR /app
COPY --from=builder /app/hostdiff .
COPY --from=builder /app/internal/http/templates ./internal/http/templates
COPY --from=builder /app/web/static ./web/static

EXPOSE 8080
CMD ["./hostdiff"]
