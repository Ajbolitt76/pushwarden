# Build from the repo root: docker build -f relay/Dockerfile -t pushwarden-relay .
FROM golang:1.26 AS build
WORKDIR /src
COPY relay/go.mod relay/go.sum ./
RUN go mod download
COPY relay/*.go ./
# Pure-Go SQLite: a static binary, no C toolchain at runtime.
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /relay . && mkdir /data

FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /relay /relay
# distroless has no shell to chown with; the nonroot user (65532) must own the volume.
COPY --from=build --chown=65532:65532 /data /data
ENV DB_PATH=/data/relay.sqlite PORT=8080
VOLUME /data
EXPOSE 8080
ENTRYPOINT ["/relay"]
