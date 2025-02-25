VERSION := $(shell git describe --always --dirty --tags)

# Strip binaries by default to make them smaller.
GO_LDFLAGS = -s -w -X github.com/rstudio/rskey/cmd.Version=$(VERSION)
GO_BUILD_ARGS = -v -trimpath

GOPATH = $(shell go env GOPATH)
ADDLICENSE = go tool github.com/google/addlicense
ADDLICENSE_ARGS = -v -s=only -l=apache -c "Posit Software, PBC" -ignore 'coverage*' -ignore '.github/**' -ignore '.goreleaser.yaml'
NOTICETOOL = go tool go.elastic.co/go-licence-detector

all: rskey

.PHONY: rskey
rskey:
	CGO_ENABLED=0 go build -ldflags="$(GO_LDFLAGS)" $(GO_BUILD_ARGS) -o $@ ./$<

.PHONY: static-build
static-build: rskey
	ldd $< 2>&1 | grep 'not a dynamic executable'

check: fmt vet

.PHONY: test
test:
	go test ./... $(GO_BUILD_ARGS) -coverprofile coverage.out
	go tool cover -html=coverage.out -o coverage.html
	go test ./... $(GO_BUILD_ARGS) -tags "fips" -coverprofile coverage-fips.out
	go tool cover -html=coverage-fips.out -o coverage-fips.html

.PHONY: fmt
fmt:
	go fmt ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: check-license
check-license:
	$(ADDLICENSE) $(ADDLICENSE_ARGS) -check .

.PHONY: license
license:
	$(ADDLICENSE) $(ADDLICENSE_ARGS) .

notice: NOTICE.md

NOTICE.md: NOTICE.md.tmpl go.mod go.sum
	go list -m -json all | $(NOTICETOOL) -noticeOut $@ -noticeTemplate $<

.PHONY: clean
clean:
	rm -f rskey
