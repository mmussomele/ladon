.PHONY: deps
deps: /usr/local/bin/openssl

/usr/local/bin/openssl:
	wget https://www.openssl.org/source/openssl-1.1.1i.tar.gz
	tar -xzf openssl-1.1.1i.tar.gz
	(cd openssl-1.1.1i && ./config && make && make test && sudo make install)
	rm -r openssl-1.1.1i.tar.gz openssl-1.1.1i
