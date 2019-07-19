
#GOPATH = $(PWD)/.go

APPNAME="udptunnel"

echo:
	@echo "$(APPNAME) with libs from $(GOPATH)"

deps:
	go get -u github.com/eyedeekay/udptunnel/common
	go get -u github.com/eyedeekay/udptunnel

build:
	go build

fmt:
	find . -name '*.go' -exec gofmt -w -s {} \;

test:
	find . -type d -path ./.git -prune -o -exec bash -c 'cd {} && go test' \;

lint:
	find . -name '*.go' -exec golint {} \;
