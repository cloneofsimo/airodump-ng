LDLIBS += -lpcap

all: main

main: main.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f main *.o