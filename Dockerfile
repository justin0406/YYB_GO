FROM golang:1.23-bookworm AS builder
WORKDIR /src
COPY yyb_go/go.mod yyb_go/go.sum ./
RUN go mod download
COPY yyb_go/ .
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w" -o /yyb-go ./cmd/yyb-go

FROM debian:bookworm-slim
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates tzdata \
    && rm -rf /var/lib/apt/lists/* \
    && useradd -r -u 1000 -m yyb

WORKDIR /app
COPY --from=builder /yyb-go /app/yyb-go
COPY yyb_go/resource /app/resource
RUN chown -R yyb:yyb /app
USER yyb

ENV TZ=Asia/Shanghai
EXPOSE 8000
VOLUME ["/app/resource"]

ENTRYPOINT ["/app/yyb-go"]
CMD ["-host", "0.0.0.0", "-port", "8000", "-resource-root", "/app/resource"]
