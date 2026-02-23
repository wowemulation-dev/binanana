PROFILES := $(wildcard profile/*)
PROFILE ?= profile/classic-1.13.2-31650-windows-win64

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

setup-ghidra:
	./script/setup-ghidra

setup-ghidra-headless:
	./script/setup-ghidra --headless

.PHONY: all compile-symbols compile-symbols-one validate validate-all clean export-from-binja setup-ghidra setup-ghidra-headless
