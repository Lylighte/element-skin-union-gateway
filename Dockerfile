FROM golang:1.26.5-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
ARG VERSION=0.1.0
RUN mkdir -p /output/data /output/secrets && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w -X github.com/Lylighte/element-skin-union-gateway/internal/service.Version=${VERSION}" -o /output/union-gateway ./cmd/union-gateway

FROM scratch AS runtime
COPY --from=build --chown=10001:10001 /output/ /app/
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER 10001:10001
WORKDIR /app
EXPOSE 8267
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD ["/app/union-gateway", "healthcheck"]
ENTRYPOINT ["/app/union-gateway"]
CMD ["serve", "-config", "/app/config.yaml"]
