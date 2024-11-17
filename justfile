set positional-arguments

all: build

run *args:
    go run ./... "$@"

build:
    go build ./...

test:
    go test -v ./...

release: test
    goreleaser release

clean:
    rm -rf dist
