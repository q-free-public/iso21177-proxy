
INSTALL_BIN_DIR=${DESTDIR}/usr/bin/
INSTALL_SYSTEMD_DIR=${DESTDIR}/lib/systemd/system
COPTS+=-Wall -std=c++14
CXXOPTS+=-Wall -std=c++14

## Q-Free special openssl with RFC8902 and ISO 21177
CXXOPTS+=-I/home/olal/openssl/include
LDFLAGS+=-L/home/olal/openssl -Wl,-rpath=/home/olal/openssl

%.o: %.cc
	$(CXX) $(CXXOPTS) -O -c $<

all: iso21177-proxy openssl-test

iso21177-proxy.o: iso21177-proxy.cc iso21177-proxy.h utils.h proxy-client.h
utils.o: utils.cc utils.h
proxy-client.o: proxy-client.cc proxy-client.h http-headers.h connection-client.h
connection-client-tcp.o: connection-client-tcp.cc connection-client.h
connection-client-tls.o: connection-client-tls.cc connection-client.h

openssl-test.o: openssl-test.cc
	$(CXX) $(CXXOPTS) -O -c $<

iso21177-proxy: iso21177-proxy.o utils.o proxy-client.o connection-client-tcp.o connection-client-tls.o
	$(CXX) $^ $(LDFLAGS) -lpthread -lssl -lcrypto -o iso21177-proxy

openssl-test: openssl-test.o
	$(CXX) $^ $(LDFLAGS) -lssl -lcrypto -o openssl-test

install: iso21177-proxy
	mkdir -p ${INSTALL_BIN_DIR}
	install iso21177-proxy ${INSTALL_BIN_DIR}
	install -d ${INSTALL_SYSTEMD_DIR}
	install -m 0644 iso-21177-proxy.service ${INSTALL_SYSTEMD_DIR}
	systemctl daemon-reload
	systemctl restart iso-21177-proxy


clean:
	rm -f *.o iso21177-proxy openssl-test
	rm -f utils.cc utils.h

#
# Include communication source code from cits-common-software/ublox/comm-factory
#
utils.cc:
	ln -s ../cits-common-software/ublox/utils.cc .
utils.h:
	ln -s ../cits-common-software/ublox/utils.h .
