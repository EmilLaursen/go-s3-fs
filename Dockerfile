FROM golang:1.15 AS download-dependencies

ARG GOOS
ARG GOARCH

WORKDIR /app

COPY . .

RUN go mod download

FROM download-dependencies as builder

ARG GOOS
ARG GOARCH

RUN GOARCH=amd64 go generate ./...
# ldflags pass options to go tool link. -s removes symbol table,
# and -w does not generate DWARF debugging info, resulting in a ~30% smaller
# binary
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o gos3fs main.go

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10 as production

COPY --from=builder /app/gos3fs /gos3fs

CMD ["/gos3fs"]

FROM discolix/static:latest-linux_arm64 as production-arm

COPY --from=builder /app/gos3fs /gos3fs

CMD ["/gos3fs"]