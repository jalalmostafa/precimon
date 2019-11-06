# Makefile for precimon for Linux
CFLAGS := $(CFLAGS) -g -O4 -pedantic -Wall
LDFLAGS = -g

TARGET = precimon
OBJS = precimon.o
TARGET_COLLECTOR = precimon_collector
OBJS_COLLECTOR = precimon_collector.o

$(TARGET): $(OBJS)

$(TARGET_COLLECTOR): $(OBJS_COLLECTOR)

clean:
	rm -f $(TARGET) $(TARGET_COLLECTOR)

