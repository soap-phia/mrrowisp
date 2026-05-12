FROM golang:1.26.3-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o mrrowisp main.go

FROM alpine:3.19

RUN apk --no-cache add ca-certificates

WORKDIR /app

COPY --from=builder /app/mrrowisp .
COPY example.config.json ./config.json

EXPOSE 6001

CMD ["./mrrowisp", "-config", "config.json"]
