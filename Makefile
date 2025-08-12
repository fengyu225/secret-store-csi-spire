VERSION ?= v0.0.4
REGISTRY ?= fengyu225
NAME ?= secrets-store-csi-provider-spire
IMAGE_TAG ?= $(VERSION)
PLATFORMS ?= linux/amd64


build:
	@echo "Building binary..."
	go build $(LDFLAGS) -o bin/spire-csi-provider cmd/spire-csi-provider/main.go

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

.PHONY: mocks
mocks:
	@echo "Generating mocks..."
	@go install github.com/golang/mock/mockgen@latest
	@mkdir -p internal/mocks
	@mockgen -source=internal/client/interface.go -destination=internal/client/mock_spire_client.go -package=client SpireClient
	@mockgen -source=internal/client/pool_interface.go -destination=internal/client/mock_client_pool.go -package=client ClientPoolInterface
	@mockgen -destination=internal/client/mock_delegated_identity.go -package=client github.com/spiffe/spire-api-sdk/proto/spire/api/agent/delegatedidentity/v1 DelegatedIdentityClient,DelegatedIdentity_SubscribeToX509SVIDsClient,DelegatedIdentity_SubscribeToX509BundlesClient

.PHONY: test
test:
	@echo "Running tests..."
	@go test -v ./...

.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	@go test -v -cover -coverprofile=coverage.out ./...
	@go tool cover -html=coverage.out -o coverage.html
