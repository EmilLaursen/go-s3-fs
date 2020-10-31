FROM golang:1.15 AS download-dependencies

ARG GOOS
ARG GOAARCH

WORKDIR /app

COPY . .

RUN go mod download

FROM download-dependencies as builder

ARG GOOS
ARG GOAARCH

ENV CGO_ENABLED=0


RUN go generate ./...
# ldflags pass options to go tool link. -s removes symbol table,
# and -w does not generate DWARF debugging info, resulting in a ~30% smaller
# binary
RUN GOOS=$GOOS GOAARCH=$GOAARCH go build -ldflags="-s -w" -o gos3fs main.go

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10 as production

COPY --from=builder /app/gos3fs /gos3fs

CMD ["/gos3fs"]