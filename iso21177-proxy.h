/*
 * iso21177-proxy.h
 */

class ProxyClient
{
public:
   std::thread *pThread;
   int          fd;
   struct sockaddr_in6 addrClient;
   std::string  addrClientStr;
   time_t       openTime;
   time_t       closeTime;
   bool         completed;
   long         recvPck;
   long         recvBytes;
   long         sendPck;
   long         sendBytes;
};

