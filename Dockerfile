FROM golang:1.15 AS download-dependencies

ARG GOOS
ARG GOARCH

WORKDIR /app

RUN go get -d github.com/cespare/reflex && go install github.com/cespare/reflex

COPY . .

RUN GOARCH=amd64 go generate ./...

RUN go mod download


FROM download-dependencies as builder

ARG GOOS
ARG GOARCH

# ldflags pass options to go tool link. -s removes symbol table,
# and -w does not generate DWARF debugging info, resulting in a ~30% smaller
# binary
RUN CGO_ENABLED=0 GOOS=$GOOS GOARCH=$GOARCH go build -ldflags="-s -w" -o gos3fs main.go


FROM download-dependencies as development

COPY --from=builder /app/gos3fs /gos3fs
COPY --from=download-dependencies /go/bin/reflex /reflex

# "/go/bin/reflex", "-rsv", "\\.go$", 
ENTRYPOINT ["/reflex", "-vsr", "\\.go$", "--", "sh", "-c", "go build -o gos3fs main.go && /gos3fs"]

# Now copy it into our base image.
FROM gcr.io/distroless/base-debian10 as production

COPY --from=builder /app/gos3fs /gos3fs

CMD ["/gos3fs"]

FROM discolix/static:latest-linux_arm64 as production-arm

COPY --from=builder /app/gos3fs /gos3fs

CMD ["/gos3fs"]