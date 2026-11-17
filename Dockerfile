FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /ssham . && mkdir /data

# Static binary on a minimal image: no shell, no package manager, non-root.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /ssham /ssham
COPY --from=build --chown=nonroot:nonroot /data /data
USER nonroot
EXPOSE 2222
ENTRYPOINT ["/ssham", "-addr", ":2222", "-host-key-dir", "/data", "-state", "/data/state.gob", "-log", "/data/ssham.jsonl"]
