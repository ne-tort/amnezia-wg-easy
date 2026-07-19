FROM golang:1.22-bookworm AS build
WORKDIR /work
COPY main.go .
RUN go mod init mtcheckhs \
 && go get github.com/gotd/td@v0.114.0 \
 && go mod tidy \
 && GOMAXPROCS=1 CGO_ENABLED=0 go build -p 1 -o /mtcheck-hs .

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /mtcheck-hs /mtcheck-hs
ENTRYPOINT ["/mtcheck-hs"]
