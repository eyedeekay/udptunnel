
#GOPATH = $(PWD)/.go

APPNAME="udptunnel"

echo:
	@echo "$(APPNAME) with libs from $(GOPATH)"

deps:
	go get -u github.com/eyedeekay/udptunnel/common
	go get -u github.com/eyedeekay/udptunnel

build:
	go build

clean:
	go clean

fmt:
	find . -name '*.go' -exec gofmt -w -s {} \;

test:
	go test -v ./filter ./tunnel

lint:
	find . -name '*.go' -exec golint {} \;
