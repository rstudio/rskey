CGO_ENABLED = 0
# Strip binaries by default to make them smaller.
GO_LDFLAGS = -s -w
# Using the 'netgo' tag opts into the native implementation and allows for
# static binaries.
GO_BUILD_ARGS = -v -tags "netgo" -trimpath

GOPATH = `go env GOPATH`
ADDLICENSE = $(GOPATH)/bin/addlicense
ADDLICENSE_ARGS = -v -s=only -l=apache -c "RStudio, PBC" -ignore 'coverage*' -ignore '.github/**' -ignore '.goreleaser.yaml'

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
	GO111MODULE=on go test ./... $(GO_BUILD_ARGS) -tags "fips" -coverprofile coverage-fips.out
	go tool cover -html=coverage-fips.out -o coverage-fips.html

.PHONY: fmt
fmt:
	GO111MODULE=on go fmt ./...

.PHONY: vet
vet:
	GO111MODULE=on go vet ./...

.PHONY: check-license
check-license:
	GO111MODULE=on $(ADDLICENSE) $(ADDLICENSE_ARGS) -check .

.PHONY: license
license:
	GO111MODULE=on $(ADDLICENSE) $(ADDLICENSE_ARGS) .

.PHONY: clean
clean:
	rm -f rskey
