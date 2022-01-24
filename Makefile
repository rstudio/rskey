all: rskey

.PHONY: rskey
rskey:
	GO111MODULE=on CGO_ENABLED=off go build -o $@ ./$<

check: fmt vet

.PHONY: test
test:
	GO111MODULE=on go test ./... -coverprofile coverage.out
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
