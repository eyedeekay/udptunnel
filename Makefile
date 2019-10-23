
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

USER_GH=eyedeekay
VERSION=0.0.6

version:
	gothub release -s $(GITHUB_TOKEN) -u $(USER_GH) -r udptunnel -t v$(VERSION) -d "version $(VERSION)"
	gothub upload -s $(GITHUB_TOKEN) -f "udptunnel" -n "udptunnel" -u $(USER_GH) -r udptunnel -t v$(VERSION) -l "udptunnel" -R

