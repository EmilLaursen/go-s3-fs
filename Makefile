.PHONY: generate

generate:
	@go generate ./...
	@echo -e "[\033[1;32mOK\033[0m] Files added to embed box!\n"

security:
	@gosec -quiet ./...
	@echo -e "[\033[1;32mOK\033[0m] Go security check was completed!\n"

docker-linux-amd64: security
	@DOCKER_BUILDKIT=1 docker build --build-arg GOOS=linux --build-arg GOARCH=amd64 --target production -t gos3fs:latest .

docker-linux-armv8: security
	@DOCKER_BUILDKIT=1 docker build --build-arg GOOS=linux --build-arg GOARCH=arm64 --target production-arm -t gos3fs:armv8-v1 .

build-arm64: docker-linux-armv8
	@docker container create --name gos3fs-temp gos3fs:armv8-v1
	@mkdir -p build/
	@docker container cp gos3fs-temp:/gos3fs ./build/gos3fs ; docker container rm gos3fs-temp

build-amd64: docker-linux-amd64
	@docker container create --name gos3fs-temp gos3fs:latest
	@mkdir -p build/
	@docker container cp gos3fs-temp:/gos3fs ./build/gos3fs ; docker container rm gos3fs-temp

