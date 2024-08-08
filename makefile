all: dhcp.out out/libradiotap.so inc/radiotap.h inc/radiotap_iter.h

dhcp.out: out/main.c.o
	clang $^ -o dhcp.out -L/usr/local/lib -lpcap -Iinc

out/main.c.o: src/main.c out
	clang $< -o $@ -c -Iinc

out: 
	mkdir out

inc:
	mkdir inc

inc/radiotap.h: lib/radiotap-library/radiotap.h inc lib/radiotap-library/.git/index
	cp $< $@

inc/radiotap_iter.h: lib/radiotap-library/radiotap_iter.h inc lib/radiotap-library/.git/index
	cp $< $@

out/libradiotap.so: lib/radiotap-library/libradiotap.so out
	cp $< $@
	touch $@

lib/radiotap-library/libradiotap.so: lib/radiotap-library/.git/index lib/radiotap-library/Makefile
	make -C lib/radiotap-library
	touch $@

lib/radiotap-library/Makefile:
	cmake -B lib/radiotap-library -S lib/radiotap-library

lib/radiotap-library/.git/index:
	git clone https://github.com/radiotap/radiotap-library lib/radiotap-library

clean:
	rm -rf lib/radiotap-library out dhcp.out inc
