MANAGED_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
SCOUT_DIR := $(abspath $(MANAGED_DIR)/..)
REPO_DIR := $(abspath $(SCOUT_DIR)/..)
BUILD_DIR ?= $(REPO_DIR)/out/build/scout
DOTNET_IMAGE ?= mcr.microsoft.com/dotnet/sdk:8.0
DOCKER ?= docker
PYTHON ?= python3
DOTNET ?= dotnet

.PHONY: windows-managed-exe managed-exe clean

windows-managed-exe: managed-exe

managed-exe:
	$(PYTHON) "$(SCOUT_DIR)/catalog/generate_targets.py"
	@if command -v $(DOTNET) >/dev/null 2>&1; then \
		echo "Building managed Scout with local $(DOTNET)"; \
		$(DOTNET) build -c Release -p:OutputPath="$(BUILD_DIR)/" "$(MANAGED_DIR)/ai_path_scout-managed.csproj"; \
	elif command -v $(DOCKER) >/dev/null 2>&1; then \
		echo "Building managed Scout with $(DOCKER) ($(DOTNET_IMAGE))"; \
		$(DOCKER) run --rm -v "$(REPO_DIR):/src" -w /src/blacklight-scout/managed $(DOTNET_IMAGE) \
			dotnet build -c Release -p:OutputPath=/src/out/build/scout/; \
	else \
		echo "managed build requires '$(DOTNET)' on PATH or Docker ('$(DOCKER)')." >&2; \
		exit 2; \
	fi

clean:
	rm -rf "$(MANAGED_DIR)/bin" "$(MANAGED_DIR)/obj"
	rm -f "$(BUILD_DIR)"/ai_path_scout-managed.exe "$(BUILD_DIR)"/ai_path_scout-managed.*
