PROFILES := $(wildcard profile/*)
PROFILE ?= profile/classic-1.13.2-31650-windows-win64
BINARY ?=

all: compile-symbols

compile-symbols:
	@for p in $(PROFILES); do \
		if [ -d "$$p/symbol" ]; then \
			echo "Compiling symbols for $$p..."; \
			./script/compile-symbols "$$p"; \
		fi; \
	done

compile-symbols-one:
	./script/compile-symbols $(PROFILE)

validate:
	python3 tools/validate_profile.py $(PROFILE)

validate-all:
	@for p in $(PROFILES); do \
		if [ -f "$$p/info.json" ]; then \
			echo "Validating $$p..."; \
			python3 tools/validate_profile.py "$$p"; \
		fi; \
	done

clean:
	@for p in $(PROFILES); do \
		rm -f "$$p/symbol/main.sym"; \
	done

export-from-binja:
	./script/export-from-binja $(PROFILE)

analyze:
	@if [ -z "$(BINARY)" ]; then \
		echo "Usage: make analyze BINARY=/path/to/binary [PROFILE=...]"; \
		exit 1; \
	fi
	./script/analyze "$(BINARY)" $(PROFILE)

setup-ghidra:
	./script/setup-ghidra

setup-ghidra-headless:
	./script/setup-ghidra --headless

build-extension:
	./script/build-extension

install-extension:
	./script/install-extension

clean-extension:
	cd extension && gradle clean 2>/dev/null; rm -rf extension/dist/

lint:
	uv run ruff check ghidra/ tools/
	uv run pyright ghidra/ tools/

lint-fix:
	uv run ruff check --fix ghidra/ tools/

.PHONY: all compile-symbols compile-symbols-one validate validate-all clean export-from-binja analyze setup-ghidra setup-ghidra-headless build-extension install-extension clean-extension lint lint-fix
