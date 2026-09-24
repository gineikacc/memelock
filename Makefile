CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=
LDLIBS  := -lraylib -lX11 -lpam -lpam_misc -lm -lGL -lpthread -ldl -lrt \
           -lXrandr -lXinerama -lXi -lXcursor

TARGET  := memelock
SRC     := memelock.c

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC)
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
