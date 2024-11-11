all: build

run *args:
    go run ./... {{ args }}

build:
    go build ./...

test:
    go test -v ./...

release: test
    goreleaser release

clean:
    rm -rf dist
