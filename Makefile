LDLIBS = -lpcap -lnet

all: tcp-block

tcp-block: tcp-block

clean:
	rm -f tcp-block *.o

remake: clean all
