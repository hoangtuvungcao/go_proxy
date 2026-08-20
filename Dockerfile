FROM golang:1.25-alpine AS builder

RUN apk add --no-cache gcc musl-dev sqlite-dev git

WORKDIR /app
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -ldflags="-s -w" -o /app/goproxy main.go

FROM alpine:latest

RUN apk add --no-cache ca-certificates sqlite-libs zmap

WORKDIR /app
COPY --from=builder /app/goproxy /app/goproxy
COPY --from=builder /app/configs /app/configs

EXPOSE 8080

ENTRYPOINT ["/app/goproxy"]
CMD ["server", "--api-addr", ":8080"]

