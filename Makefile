
LDFLAGS=-lrt -lpcap
CPPFLAGS=-Wall 

all: rx tx

%.o: %.c *.h
	gcc -c -o $@ $< $(CPPFLAGS)

%.o: %.cpp *.hpp *.h
	g++ -std=c++11 -c -o $@ $< $(CPPFLAGS)

rx: rx.o radiotap.o fec.o
	g++ -o $@ $^ $(LDFLAGS)


tx: tx.o fec.o
	g++ -o $@ $^ $(LDFLAGS)


clean:
	rm -f rx tx *~ *.o

