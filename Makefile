CC=g++
CFLAGS=-Wall -I/usr/local/include -O3
CFLAGSLINK=-lgmp -lpthread -L/usr/local/lib/ -lssl -lcrypto -lopencv_core -lopencv_highgui -lopencv_imgproc -lopencv_videoio -lopencv_imgcodecs
SOURCES=

all: unicorn clean
unicorn: sloth.o main.o
	$(CC) sloth.o main.o $(CFLAGS) $(CFLAGSLINK) -o unicorn
main.o:
	$(CC) main.cpp $(SOURCES) $(CFLAGS) -c
sloth.o:
	$(CC) sloth.cpp sloth.h $(SOURCES) $(CFLAGS) -c
clean:
	rm -rf *.o
	rm -rf *.h.gch
	rm -rf *.h.gch
