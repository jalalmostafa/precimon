# Makefile for njmon for Linux
CFLAGS=-g -O4
LDFLAGS=-g

FILE=njmon_linux_v30.c
OUT=njmon

$(OUT): 
	cc $(CFLAGS) -o $(OUT) $(FILE) $(LDFLAGS)

clean:
	rm $(OUT)

