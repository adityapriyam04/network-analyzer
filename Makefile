CC = gcc
CFLAGS = -std=gnu11 -Wall -Wextra -O2 -pthread
LDFLAGS = -lpcap -pthread

SRCS = src/main.c src/capture.c src/decoder.c src/tracker.c src/metrics.c
TARGET = analyzer

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LDFLAGS)

clean:
	rm -f $(TARGET)
