NATIVE_DIR := $(abspath $(dir $(lastword $(MAKEFILE_LIST))))
CATALOG_DIR := $(abspath $(NATIVE_DIR)/../catalog)
BOF_DIR := $(abspath $(NATIVE_DIR)/../bofs/ai_path_scout)
REPO_DIR := $(abspath $(NATIVE_DIR)/../..)
BUILD_DIR ?= $(REPO_DIR)/out/build/scout
OBJ_DIR := $(BUILD_DIR)/obj

CC_X64 ?= x86_64-w64-mingw32-gcc
CC_POSIX ?= cc
STRIP_X64 ?= strip
ALLOW_CROSS_DARWIN ?=
MACOS_MIN ?= 11.0
LIPO ?= lipo

BOF_CFLAGS := -Os -std=c99 \
	-DBLACKLIGHT_SCOUT_WINDOWS \
	-I$(NATIVE_DIR) -I$(CATALOG_DIR) \
	-fno-stack-protector -fno-stack-check -mno-stack-arg-probe \
	-fno-builtin -fno-builtin-memset -fno-builtin-memcpy -fno-builtin-memmove \
	-nostdlib \
	-fno-asynchronous-unwind-tables -fno-unwind-tables -fno-ident \
	-Wall -Wextra -Wno-unused-parameter -Wno-unused-variable \
	-fno-leading-underscore -fno-ms-extensions

POSIX_CFLAGS := -Os -std=c99 -Wall -Wextra -Wno-unused-parameter -I$(NATIVE_DIR) -I$(CATALOG_DIR)
POSIX_LDFLAGS_DYLIB := -dynamiclib -mmacosx-version-min=$(MACOS_MIN) -Wl,-install_name,@rpath/libai_path_scout.dylib
POSIX_LDFLAGS_SO := -shared -fPIC

BOF_SOURCES := ai_path_scout_bof.c ai_path_scout_core.c
POSIX_SOURCES := ai_path_scout_posix.c ai_path_scout_core.c
WINDOWS_EXE_SOURCES := ai_path_scout_windows.c ai_path_scout_core.c

.PHONY: all bof posix dylib so standalone windows-exe windows-exe-target-cap-test macos-exe linux-exe smoke clean

all: bof posix

bof: $(BUILD_DIR)/ai_path_scout.x64.o

posix: smoke dylib so

BOF_BOF_OBJ := $(OBJ_DIR)/ai_path_scout_bof.x64.o
BOF_CORE_OBJ := $(OBJ_DIR)/ai_path_scout_core.x64.o

$(BUILD_DIR)/ai_path_scout.x64.o: $(BOF_BOF_OBJ) $(BOF_CORE_OBJ)
	@echo "Linking x64 BOF relocatable object: $@"
	@mkdir -p $(@D)
	$(CC_X64) -r -o $@ $(BOF_BOF_OBJ) $(BOF_CORE_OBJ)
	@if command -v $(STRIP_X64) >/dev/null 2>&1; then \
		$(STRIP_X64) --strip-unneeded $@ 2>/dev/null || true; \
	fi

$(BOF_BOF_OBJ): $(NATIVE_DIR)/ai_path_scout_bof.c $(CATALOG_DIR)/static_targets_generated.h $(NATIVE_DIR)/ai_path_scout_core.h $(NATIVE_DIR)/beacon.h
	@echo "Building x64 BOF wrapper: $@"
	@mkdir -p $(@D)
	$(CC_X64) $(BOF_CFLAGS) -c -o $@ $<

$(BOF_CORE_OBJ): $(NATIVE_DIR)/ai_path_scout_core.c $(NATIVE_DIR)/ai_path_scout_core.h
	@echo "Building x64 BOF core: $@"
	@mkdir -p $(@D)
	$(CC_X64) $(BOF_CFLAGS) -c -o $@ $<

$(BUILD_DIR)/ai_path_scout_smoke: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building POSIX smoke binary: $@"
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/ai_path_scout-windows-x64.exe: $(addprefix $(NATIVE_DIR)/,$(WINDOWS_EXE_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building Windows standalone Scout: $@"
	@mkdir -p $(@D)
	$(CC_X64) -Os -std=c99 -DBLACKLIGHT_SCOUT_WINDOWS -I$(NATIVE_DIR) -I$(CATALOG_DIR) -o $@ $(NATIVE_DIR)/ai_path_scout_windows.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/ai_path_scout-macos: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building macOS standalone Scout: $@"
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/ai_path_scout-linux-x64: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building Linux standalone Scout: $@"
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/libai_path_scout-arm64.dylib: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building macOS arm64 dylib: $@"
	@if [ "$$(uname -s)" != "Darwin" ] && [ -z "$(ALLOW_CROSS_DARWIN)" ]; then \
		echo "macOS dylib must be built on macOS, or set ALLOW_CROSS_DARWIN=1 with a real Darwin cross toolchain."; \
		exit 2; \
	fi
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) -arch arm64 $(POSIX_LDFLAGS_DYLIB) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/libai_path_scout-x86_64.dylib: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building macOS x86_64 dylib: $@"
	@if [ "$$(uname -s)" != "Darwin" ] && [ -z "$(ALLOW_CROSS_DARWIN)" ]; then \
		echo "macOS dylib must be built on macOS, or set ALLOW_CROSS_DARWIN=1 with a real Darwin cross toolchain."; \
		exit 2; \
	fi
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) -arch x86_64 $(POSIX_LDFLAGS_DYLIB) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

$(BUILD_DIR)/libai_path_scout.dylib: $(BUILD_DIR)/libai_path_scout-arm64.dylib $(BUILD_DIR)/libai_path_scout-x86_64.dylib
	@echo "Creating universal macOS dylib: $@"
	$(LIPO) -create -output $@ $^

$(BUILD_DIR)/libai_path_scout.so: $(addprefix $(NATIVE_DIR)/,$(POSIX_SOURCES)) $(CATALOG_DIR)/static_targets_generated.h
	@echo "Building Linux shared object: $@"
	@mkdir -p $(@D)
	$(CC_POSIX) $(POSIX_CFLAGS) $(POSIX_LDFLAGS_SO) -o $@ $(NATIVE_DIR)/ai_path_scout_posix.c $(NATIVE_DIR)/ai_path_scout_core.c

smoke: $(BUILD_DIR)/ai_path_scout_smoke
	@echo "Running POSIX smoke test"
	@$(BUILD_DIR)/ai_path_scout_smoke | head -n 5

dylib: $(BUILD_DIR)/libai_path_scout.dylib

so: $(BUILD_DIR)/libai_path_scout.so

standalone: macos-exe linux-exe

windows-exe: $(BUILD_DIR)/ai_path_scout-windows-x64.exe

windows-exe-target-cap-test:
	@echo "Building Windows target-cap regression executable"
	@mkdir -p $(BUILD_DIR)
	$(CC_X64) -Os -std=c99 -DBLACKLIGHT_SCOUT_WINDOWS -DBL_MAX_OPERATOR_TARGETS=4 -I$(NATIVE_DIR) -I$(CATALOG_DIR) \
		-o $(BUILD_DIR)/ai_path_scout-windows-target-cap-test.exe $(NATIVE_DIR)/ai_path_scout_windows.c $(NATIVE_DIR)/ai_path_scout_core.c

macos-exe: $(BUILD_DIR)/ai_path_scout-macos

linux-exe: $(BUILD_DIR)/ai_path_scout-linux-x64

clean:
	rm -rf $(OBJ_DIR)
	rm -f $(BUILD_DIR)/ai_path_scout.x64.o \
		$(BOF_DIR)/ai_path_scout.x64.o \
		$(BUILD_DIR)/ai_path_scout-windows-x64.exe \
		$(NATIVE_DIR)/ai_path_scout-windows-x64.exe \
		$(BUILD_DIR)/ai_path_scout-macos \
		$(NATIVE_DIR)/ai_path_scout-macos \
		$(BUILD_DIR)/ai_path_scout-linux-x64 \
		$(NATIVE_DIR)/ai_path_scout-linux-x64 \
		$(BUILD_DIR)/ai_path_scout_smoke \
		$(NATIVE_DIR)/ai_path_scout_smoke \
		$(BUILD_DIR)/libai_path_scout.dylib \
		$(BUILD_DIR)/libai_path_scout-arm64.dylib \
		$(BUILD_DIR)/libai_path_scout-x86_64.dylib \
		$(NATIVE_DIR)/libai_path_scout.dylib \
		$(BUILD_DIR)/libai_path_scout.so \
		$(NATIVE_DIR)/libai_path_scout.so
