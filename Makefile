.PHONY: build install clean help

BINARY_NAME=reconcombo
GITHUB_USERNAME=nickyqqq
GITHUB_REPO=reconcomboGo
INSTALL_PATH=$(HOME)/.local/bin

help:
	@echo "Usage:"
	@echo "  make build      - Build the binary (output: ./reconcombo)"
	@echo "  make install    - Build and install to $(INSTALL_PATH)"
	@echo "  make clean      - Remove built binary"
	@echo "  make release    - Build for all platforms (Linux, macOS, Windows)"

build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

install: build
	@echo "Installing $(BINARY_NAME) to $(INSTALL_PATH)..."
	mkdir -p $(INSTALL_PATH)
	cp $(BINARY_NAME) $(INSTALL_PATH)/$(BINARY_NAME)
	chmod +x $(INSTALL_PATH)/$(BINARY_NAME)
	@echo "✓ Installation complete!"
	@echo "Make sure $(INSTALL_PATH) is in your PATH"
	@echo "You can now run: reconcombo --url target.com"

clean:
	@echo "Cleaning up..."
	rm -f $(BINARY_NAME)
	rm -f $(BINARY_NAME)-linux
	rm -f $(BINARY_NAME)-darwin
	rm -f $(BINARY_NAME)-windows.exe

release:
	@echo "Building for all platforms..."
	GOOS=linux GOARCH=amd64 go build -o $(BINARY_NAME)-linux .
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-darwin .
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME)-windows.exe .
	@echo "✓ Builds complete:"
	@echo "  - $(BINARY_NAME)-linux"
	@echo "  - $(BINARY_NAME)-darwin"
	@echo "  - $(BINARY_NAME)-windows.exe"
