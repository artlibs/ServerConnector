APP_NAME := sc
CONFIG_DIR := /etc/$(APP_NAME)
CONFIG_FILE := $(CONFIG_DIR)/config.yml
BIN_PATH := /usr/local/bin/$(APP_NAME)

init:
	@go mod init $(APP_NAME)
	@go mod tidy

build:
	@go build -o $(APP_NAME) $(APP_NAME).go

install: build
	@echo "Installing sc..."
	@mkdir -p /usr/local/bin
	@cp sc /usr/local/bin/
	@chmod +x /usr/local/bin/sc
	@mkdir -p /etc/sc
	@if [ ! -f /etc/sc/config.yml ]; then \
		echo "Creating default config.yml..."; \
		echo "# SSH客户端全局配置" > /etc/sc/config.yml; \
		echo "ssh_path: /usr/bin/ssh" >> /etc/sc/config.yml; \
		echo "sshpass_path: /usr/local/bin/sshpass" >> /etc/sc/config.yml; \
		echo "" >> /etc/sc/config.yml; \
		echo "# 服务器配置" >> /etc/sc/config.yml; \
		echo "servers:" >> /etc/sc/config.yml; \
		echo "  example:" >> /etc/sc/config.yml; \
		echo "    host: \"192.168.1.100\"" >> /etc/sc/config.yml; \
		echo "    port: \"22\"" >> /etc/sc/config.yml; \
		echo "    user: \"user\"" >> /etc/sc/config.yml; \
		echo "    auth_method: \"ask\"" >> /etc/sc/config.yml; \
		echo "    admin: \"root\"" >> /etc/sc/config.yml; \
		echo "    desc: \"Example Server\"" >> /etc/sc/config.yml; \
		echo "" >> /etc/sc/config.yml; \
		echo "# 环境配置" >> /etc/sc/config.yml; \
		echo "environments:" >> /etc/sc/config.yml; \
		echo "  current: \"default\"" >> /etc/sc/config.yml; \
		echo "  default:" >> /etc/sc/config.yml; \
		echo "    ssh_home: \"~/.ssh\"" >> /etc/sc/config.yml; \
		echo "    git_config: \"~/.gitconfig\"" >> /etc/sc/config.yml; \
		echo "    desc: \"默认开发环境\"" >> /etc/sc/config.yml; \
	fi
	@mkdir -p /etc/sc/ssh.default
	@if [ ! -f /etc/sc/gitconfig.default ]; then \
		echo "Creating default gitconfig..."; \
		echo "[user]" > /etc/sc/gitconfig.default; \
		echo "	name = Default User" >> /etc/sc/gitconfig.default; \
		echo "	email = default@example.com" >> /etc/sc/gitconfig.default; \
	fi
	@echo "Installation complete"
	@echo "Edit /etc/sc/config.yml to configure."

uninstall:
	@rm -f ${BIN_PATH}
	@echo 'sc removed from your system :)'
