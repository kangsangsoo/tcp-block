LDLIBS = -lpcap -lnet

all: tcp-block

tcp-block: tcp-block.o tcphdr.o mac.o iphdr.o ip.o ethhdr.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ 

clean:
	rm -f tcp-block *.o

remake: clean all