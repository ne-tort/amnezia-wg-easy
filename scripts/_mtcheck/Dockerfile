FROM golang:1.25-bookworm AS build
WORKDIR /work
COPY main.go .
RUN go mod init mtcheck \
 && go get github.com/gotd/td@e7d5e7882d4a \
 && go mod tidy \
 && GOMAXPROCS=1 CGO_ENABLED=0 go build -p 1 -ldflags="-s -w" -o /mtcheck .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /mtcheck /mtcheck
ENTRYPOINT ["/mtcheck"]
