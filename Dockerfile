# syntax=docker/dockerfile:1
FROM golang:1.27.3-alpine AS build
WORKDIR /src
COPY go.mod ./
COPY cmd ./cmd
COPY internal ./internal
RUN CGO_ENABLED=0 go build -trimpath -ldflags='-s -w' -o /spamgate ./cmd/spamgate

FROM alpine:3.23
RUN apk add --no-cache ca-certificates && addgroup -S spamgate && adduser -S -G spamgate spamgate && mkdir -p /var/lib/spamgate && chown spamgate:spamgate /var/lib/spamgate
COPY --from=build /spamgate /usr/local/bin/spamgate
USER spamgate:spamgate
WORKDIR /var/lib/spamgate
VOLUME ["/var/lib/spamgate"]
EXPOSE 38470 38471 38472 38473 38474
ENTRYPOINT ["/usr/local/bin/spamgate","-internal-supervise"]
CMD ["-data","/var/lib/spamgate","-listen","0.0.0.0:38470"]
