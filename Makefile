
INSTALL_BIN_DIR=${DESTDIR}/usr/bin/
COPTS+=-Wall -std=c++14
CXXOPTS+=-Wall -std=c++14

%.o: %.cc
	$(CXX) $(CXXOPTS) -O -c $<

all: iso21177-proxy

iso21177-proxy.o: iso21177-proxy.cc iso21177-proxy.h utils.h
utils.o: utils.cc utils.h

iso21177-proxy: iso21177-proxy.o utils.o
	$(CXX) $^ $(LDFLAGS) -lpthread -o iso21177-proxy

install: iso21177-proxy
	mkdir -p ${INSTALL_BIN_DIR}
	install iso21177-proxy ${INSTALL_BIN_DIR}

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
