export TARGET := iphone:clang:latest:14.0
export ARCHS = arm64
export THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = ShanLianAD
ShanLianAD_FILES = Tweak.x
ShanLianAD_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
ShanLianAD_LDFLAGS = -Wl,-undefined,dynamic_lookup

include $(THEOS_MAKE_PATH)/tweak.mk
