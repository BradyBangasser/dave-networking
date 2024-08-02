dhcp.out: out/main.c.o
	clang $^ -o dhcp.out -L/usr/local/lib -lpcap

out/main.c.o: src/main.c
	clang $^ -o $@ -c
