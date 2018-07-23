SYSCTL_FILE=./sysctl.conf
DATA_DIR=./ELK_DATA

all: sysctl data_dir
	docker-compose up

clean:
	docker-compose down

sysctl:
	@sudo sysctl -p $(SYSCTL_FILE)

data_dir:
	@chmod 777 $(DATA_DIR)

.PHONY: all clean
