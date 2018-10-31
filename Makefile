
GOPATH = $(PWD)/.go

APPNAME="udptunnel"

echo:
	@echo "$(APPNAME) with libs from $(GOPATH)"

deps:
	go get -u github.com/eyedeekay/udptunnel

build:
	go build
