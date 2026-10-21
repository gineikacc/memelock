CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2
LDFLAGS ?=
LDLIBS  := -lraylib -lX11 -lpam -lpam_misc -lm -lGL -lpthread -ldl -lrt \
           -lXrandr -lXinerama -lXi -lXcursor -lcurl -ljson-c

TARGET  := memelock
SRC     := memelock.c dvd_logo.c
HDR     := dvd_logo.h

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRC) $(HDR)
	$(CC) $(CFLAGS) -o $@ $(SRC) $(LDFLAGS) $(LDLIBS)

clean:
	rm -f $(TARGET)
