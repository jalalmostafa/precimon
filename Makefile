# Makefile for precimon for Linux
CFLAGS := $(CFLAGS) -g -O4 -pedantic -Wall
LDFLAGS = -g

TARGET = precimon
OBJS = precimon.o
TARGET_PREKERNEL_2_6_18 = pre2618
TARGET_COLLECTOR = precimon_collector
OBJS_COLLECTOR = precimon_collector.o

$(TARGET): $(OBJS)

$(TARGET_COLLECTOR): $(OBJS_COLLECTOR)

all: $(TARGET) $(TARGET_COLLECTOR)

clean:
	rm -f $(TARGET) $(TARGET_COLLECTOR)

cleanall: clean
	rm -f *.o *.json *.err