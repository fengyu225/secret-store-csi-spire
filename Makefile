VERSION ?= v0.0.2
REGISTRY ?= fengyu225
NAME ?= secrets-store-csi-provider-spire
IMAGE_TAG ?= $(VERSION)
PLATFORMS ?= linux/amd64


build:
	@echo "Building binary..."
	go build $(LDFLAGS) -o bin/spire-csi-provider cmd/spire-csi-provider/main.go

test:
	@echo "Running tests..."
	go test -v ./...

docker-build:
	@echo "Building docker image $(IMAGE)..."
	docker build --platform linux/amd64 -t $(REGISTRY)/$(NAME):$(IMAGE_TAG) -f Dockerfile .

docker-push:
	@echo "Pushing docker image $(IMAGE)..."
	docker push $(REGISTRY)/$(NAME):$(IMAGE_TAG)

clean:
	@echo "Cleaning up..."
	rm -rf bin/
	go clean

docker-shell: docker-build
	@echo "Starting container shell..."
	docker run -it --rm --entrypoint=/bin/sh $(IMAGE)
