FROM golang:1.21.7-alpine AS builder

WORKDIR /app

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux go build -o mrrowisp main.go

FROM alpine:3.19

RUN apk --no-cache add ca-certificates && addgroup -S mrrowisp && adduser -S mrrowisp -G mrrowisp

WORKDIR /app

COPY --from=builder /app/mrrowisp .

USER mrrowisp

EXPOSE 6001

CMD ["./mrrowisp", "-config", "config.json"]
