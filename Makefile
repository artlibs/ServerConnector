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
	@mkdir -p $(CONFIG_DIR)
	@mv -f $(APP_NAME) $(BIN_PATH)
	@chmod +x $(BIN_PATH)
	@if [ ! -f $(CONFIG_FILE) ]; then \
		echo "ssh_path: /usr/bin/ssh" >> $(CONFIG_FILE); \
		echo "sshpass_path: /usr/local/bin/sshpass" >> $(CONFIG_FILE); \
		echo "servers:" >> $(CONFIG_FILE); \
		echo "  db1:" >> $(CONFIG_FILE); \
		echo "    port: 22" >> $(CONFIG_FILE); \
		echo "    host: 192.168.3.5" >> $(CONFIG_FILE); \
		echo "    user: ecs-user" >> $(CONFIG_FILE); \
		echo "    pass: 1234567890" >> $(CONFIG_FILE); \
		echo "    admin: root" >> $(CONFIG_FILE); \
		echo "    spass: 1234567890" >> $(CONFIG_FILE); \
		echo "    auth_method: key" >> $(CONFIG_FILE); \
		echo "    key_file: id_rsa_db1" >> $(CONFIG_FILE); \
		echo "    admin_key_file: id_rsa_admin" >> $(CONFIG_FILE); \
		echo "    desc: this is a description" >> $(CONFIG_FILE); \
	fi
	@rm -f $(APP_NAME)
	@echo 'sc installed to ${BIN_PATH} with config ${CONFIG_FILE}. Enjoy :)'

uninstall:
	@rm -f ${BIN_PATH}
	@echo 'sc removed from your system :)'
