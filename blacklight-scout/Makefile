SCOUT_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
REPO_DIR := $(abspath $(SCOUT_DIR)/..)
PYTHON ?= python3
DOCKER ?= docker
SCOUT_BUILD_IMAGE ?= blacklight-scout-build

.PHONY: release-local release-docker release-windows release-macos release-linux verify-local verify-all clean

release-local:
	$(PYTHON) "$(SCOUT_DIR)/catalog/generate_targets.py"
	$(MAKE) -C "$(SCOUT_DIR)" release-windows PYTHON="$(PYTHON)"
	$(MAKE) -C "$(SCOUT_DIR)" release-linux PYTHON="$(PYTHON)"
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform local

# Preferred local path: one Linux container with MinGW, gcc, Make, Python, and .NET SDK.
# Host only needs Docker. Produces the release-local matrix (not macOS dylib).
release-docker:
	$(DOCKER) build -t "$(SCOUT_BUILD_IMAGE)" -f "$(SCOUT_DIR)/Dockerfile" "$(SCOUT_DIR)"
	$(DOCKER) run --rm -v "$(REPO_DIR):/src" -w /src "$(SCOUT_BUILD_IMAGE)"

release-windows:
	$(PYTHON) "$(SCOUT_DIR)/catalog/generate_targets.py"
	$(MAKE) -C "$(SCOUT_DIR)/native" bof windows-exe
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform windows

release-macos:
	$(PYTHON) "$(SCOUT_DIR)/catalog/generate_targets.py"
	$(MAKE) -C "$(SCOUT_DIR)/native" dylib
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform macos

release-linux:
	$(PYTHON) "$(SCOUT_DIR)/catalog/generate_targets.py"
	$(MAKE) -C "$(SCOUT_DIR)/native" so
	$(MAKE) -C "$(SCOUT_DIR)/managed" windows-managed-exe PYTHON="$(PYTHON)"
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform linux

verify-local:
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform local

verify-all:
	$(PYTHON) "$(SCOUT_DIR)/releases/verify_matrix.py" --platform all

clean:
	$(MAKE) -C "$(SCOUT_DIR)/native" clean
	$(MAKE) -C "$(SCOUT_DIR)/managed" clean
