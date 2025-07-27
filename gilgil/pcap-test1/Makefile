CC = gcc
CFLAGS = -Wall -O2
TARGET = pcap-test
SRCS = pcap-test.c
LIBS = -lpcap

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CC) $(CFLAGS) -o $(TARGET) $(SRCS) $(LIBS)

clean:
	rm -f $(TARGET)
