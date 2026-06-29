.PHONY: build demo clean test integration-test

SRC_DIR  := .demo/orig
MNT_DIR  := .demo/mnt
STAGE_DIR := .demo/staging
BIN      := ./shadowfs

build:
	go build -o $(BIN) .

test:
	go test ./backend/ -v

integration-test: build
	python3 tests/integration_test.py -v

demo: build
	@mkdir -p $(SRC_DIR) $(MNT_DIR) $(STAGE_DIR)
	@echo "orig:    $(SRC_DIR)"
	@echo "mnt:     $(MNT_DIR)"
	@echo "staging: $(STAGE_DIR)"
	$(BIN) -staging $(STAGE_DIR) $(MNT_DIR) $(SRC_DIR)

clean:
	-fusermount -u $(MNT_DIR) 2>/dev/null
	rm -rf .demo
	rm -f $(BIN)
