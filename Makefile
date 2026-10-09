# Makefile — libshadow (clang-only, no theos) + SentinelForge
SDK_IPHONE := $(shell xcrun --show-sdk-path --sdk iphoneos 2>/dev/null)
CFLAGS_SHADOW = -arch arm64 -arch arm64e -mios-version-min=15.0 -fobjc-arc \
  -Wall -Wno-unused-parameter -Wno-deprecated-declarations -Wno-unused-function

all: libshadow.dylib

libshadow.dylib: libshadow.m fishhook.c fishhook.h
	xcrun -sdk iphoneos clang $(CFLAGS_SHADOW) -dynamiclib -o $@ libshadow.m fishhook.c \
	  -framework Foundation -framework Security

# theos path (needs THEOS env + signature identity; kept for CI/lab with identities)
theos:
	@echo "theos build: $(THEOS)/makefiles/common.mk"

test-log:
	python3 shadow_log.py --all | tail -20

clean:
	rm -f libshadow.dylib

.PHONY: all theos test-log clean
