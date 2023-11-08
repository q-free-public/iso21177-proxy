iso21177-proxy
--------------


Typical HTTP headers from Chrome
--------------------------------
GET /ruc/wormholeobjects.html HTTP/1.1
Host: localhost:8080
Connection: keep-alive
Cache-Control: max-age=0
sec-ch-ua: "Google Chrome";v="117", "Not;A=Brand";v="8", "Chromium";v="117"
sec-ch-ua-mobile: ?0
sec-ch-ua-platform: "Windows"
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Sec-Fetch-Site: none
Sec-Fetch-Mode: navigate
Sec-Fetch-User: ?1
Sec-Fetch-Dest: document
Accept-Encoding: gzip, deflate, br
Accept-Language: nb-NO,nb;q=0.9,en-GB;q=0.8,en;q=0.7,no;q=0.6,nn;q=0.5,en-US;q=0.4,sv;q=0.3,da;q=0.2,de;q=0.1,it;q=0.1


Q-Free openssl with RFC8902 and ISO 21177 support
-------------------------------------------------

$ ./Configure
$ make
$ make test

Linking apps:
$(CC) -g -I$(OPENSSL_DIR)/include -L$(OPENSSL_DIR) \
and running:
LD_LIBRARY_PATH=$(OPENSSL_DIR) ./tls_client

Or use Makefile settings:
CXXOPTS+=-I/home/olal/openssl/include
LDFLAGS+=-L/home/olal/openssl -Wl,-rpath=/home/olal/openssl
