TARGET := iphone:clang:18.6:15.0
ARCHS := arm64
INSTALL_TARGET_PROCESSES = YouTube

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = QualityProbe
QualityProbe_FILES = Tweak.m
QualityProbe_CFLAGS = -fobjc-arc
QualityProbe_FRAMEWORKS = Foundation UIKit

include $(THEOS_MAKE_PATH)/tweak.mk
