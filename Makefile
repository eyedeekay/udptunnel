
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
VERSION=0.0.1

version:
	gothub release -s $(GITHUB_TOKEN) -u $(USER_GH) -r go-anonvpn -t v$(VERSION) -d "Privacy-Enhanced VPN"
	gothub upload -s $(GITHUB_TOKEN) -f "go-anonvpn-installer.exe" -n "go-anonvpn-installer.exe" -u $(USER_GH) -r go-anonvpn -t v$(VERSION) -l "Privacy-Enhanced VPN(Windows)" -R

