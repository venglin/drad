CC=gcc
CFLAGS=-c -Wall
LDFLAGS=
SOURCES=drad.c
OBJECTS=$(SOURCES:.c=.o)
EXECUTABLE=drad

all: $(SOURCES) $(EXECUTABLE)
	
$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $@

.c.o:
	$(CC) $(CFLAGS) $< -o $@

