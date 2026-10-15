# Build stage.
FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o /out/discord-google-sso ./cmd/discord-google-sso

# Runtime stage.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/discord-google-sso /discord-google-sso
# CA certificates for the real Discord/Google endpoints.
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
USER nonroot:nonroot
ENTRYPOINT ["/discord-google-sso"]
CMD ["serve"]
