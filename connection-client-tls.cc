// connection-client-tls.cc

#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#include "iso21177-proxy.h"
#include "connection-client.h"

ConnectionClientTls::ConnectionClientTls()
{
}

ConnectionClientTls::~ConnectionClientTls()
{
	close();
}
	
bool ConnectionClientTls::connect(const std::string &host, int port)
{
	if (port <= 0)
		return false;
	if (host.size() == 0)
		return false;

   return false;
}

bool ConnectionClientTls::send(const void *data_p, unsigned int len)
{
	return false;
}

int ConnectionClientTls::recv(unsigned char *data, unsigned int maxlen)
{
	return -1;
}

void ConnectionClientTls::close()
{
}
