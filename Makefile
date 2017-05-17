
LDFLAGS=-lrt -lpcap -lsodium
CPPFLAGS=-Wall -g

all: rx tx keygen

%.o: %.c *.h
	$(CC) -c -o $@ $< $(CPPFLAGS)

%.o: %.cpp *.hpp *.h
	$(CXX) -std=gnu++11 -c -o $@ $< $(CPPFLAGS)

rx: rx.o radiotap.o fec.o wifibroadcast.o
	$(CXX) -o $@ $^ $(LDFLAGS)


tx: tx.o fec.o wifibroadcast.o
	$(CXX) -o $@ $^ $(LDFLAGS)

keygen: keygen.o
	$(CC) -o $@ $^ $(LDFLAGS)

clean:
	rm -f rx tx *~ *.o

