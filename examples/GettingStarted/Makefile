SOURCES := $(shell ls -tp *.ino | grep -v /$ | head -1)
BOARD_TAG := uno
#MONITOR_PORT := /dev/ttyACM0
#LIBRARIES := LedControl
#include /usr/share/Arduino-Makefile/arduino-mk/Arduino.mk
CFLAGS   := $(CFLAGS)   -DTWI_BUFFER_LENGTH=16 -DMAX_TIMERS=2 # -DUSE_MP3_REFILL_MEANS=USE_MP3_SimpleTimer
CXXFLAGS := $(CXXFLAGS) -DTWI_BUFFER_LENGTH=16 -DMAX_TIMERS=2 # -DUSE_MP3_REFILL_MEANS=USE_MP3_SimpleTimer

include $(shell echo $(HOME))/sketchbook/Arduino-Makefile/arduino-mk/Arduino.mk
