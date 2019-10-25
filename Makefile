# Makefile for precimon for Linux
CFLAGS=-g -O4
LDFLAGS=-g

FILE=precimon.c
FILE_COLLECTOR=precimon_collector.c
OUT=precimon
OUT_COLLECTOR=collector

.PHONY: clean $(OUT_COLLECTOR) $(OUT) all

all: $(OUT) $(OUT_COLLECTOR)

$(OUT):
	cc $(CFLAGS) -o $(OUT) $(FILE) $(LDFLAGS)

$(OUT_COLLECTOR):
	cc $(CFLAGS) -o $(OUT_COLLECTOR) $(FILE_COLLECTOR) $(LDFLAGS)

clean:
	rm $(OUT) $(OUT_COLLECTOR)

