
INSTALL_BIN_DIR=${DESTDIR}/usr/bin/
INSTALL_SYSTEMD_DIR=${DESTDIR}/lib/systemd/system
COPTS+=-Wall -std=c++14
CXXOPTS+=-Wall -std=c++14

%.o: %.cc
	$(CXX) $(CXXOPTS) -O -c $<

all: iso21177-proxy

iso21177-proxy.o: iso21177-proxy.cc iso21177-proxy.h utils.h http-headers.h
utils.o: utils.cc utils.h

iso21177-proxy: iso21177-proxy.o utils.o
	$(CXX) $^ $(LDFLAGS) -lpthread -o iso21177-proxy

install: iso21177-proxy
	mkdir -p ${INSTALL_BIN_DIR}
	install iso21177-proxy ${INSTALL_BIN_DIR}
	install -d ${INSTALL_SYSTEMD_DIR}
	install -m 0644 iso-21177-proxy.service ${INSTALL_SYSTEMD_DIR}
	sudo systemctl restart iso-21177-proxy


clean:
	rm -f *.o iso21177-proxy
	rm -f utils.cc utils.h

#
# Include communication source code from cits-common-software/ublox/comm-factory
#
utils.cc:
	ln -s ../cits-common-software/ublox/utils.cc .
utils.h:
	ln -s ../cits-common-software/ublox/utils.h .
