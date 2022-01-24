CGO_ENABLED = 0
# Strip binaries by default to make them smaller.
GO_LDFLAGS = -s -w
# Using the 'netgo' tag opts into the native implementation and allows for
# static binaries.
GO_BUILD_ARGS = -v -tags "netgo"

all: rskey

.PHONY: rskey
rskey:
	GO111MODULE=on CGO_ENABLED=$(CGO_ENABLED) go build \
		-ldflags="$(GO_LDFLAGS)" $(GO_BUILD_ARGS) -o $@ ./$<

.PHONY: static-build
static-build: rskey
	ldd $< 2>&1 | grep 'not a dynamic executable'

check: fmt vet

.PHONY: test
test:
	GO111MODULE=on go test ./... $(GO_BUILD_ARGS) -coverprofile coverage.out
	go tool cover -html=coverage.out -o coverage.html

.PHONY: fmt
fmt:
	GO111MODULE=on go fmt ./...

.PHONY: vet
vet:
	GO111MODULE=on go vet ./...

.PHONY: clean
clean:
	rm -f rskey
