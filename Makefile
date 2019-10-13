# Makefile for precimon for Linux
CFLAGS=-g -O4
LDFLAGS=-g

FILE=precimon.c
OUT=precimon

$(OUT):
	cc $(CFLAGS) -o $(OUT) $(FILE) $(LDFLAGS)

clean:
	rm $(OUT) *.json *.err

