FROM golang:1.17 as builder

WORKDIR /app

COPY go.mod .
COPY go.sum .
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build .

FROM scratch
COPY --from=builder /app/oauth /app/
COPY --from=builder /app/.env /
COPY --from=builder /app/html/. /html/

EXPOSE 8080

ENTRYPOINT [ "/app/oauth" ]