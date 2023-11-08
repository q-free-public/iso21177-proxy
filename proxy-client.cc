// proxy-client.cc

#include <stdlib.h>
#include <unistd.h>

#include "proxy-client.h"
#include "http-headers.h"
#include "connection-client.h"

void ProxyClient::client_proc()
{
   if (optVerbose) {
      printf("Starting proxyPlainClientProc fd=%d\n", fd);
   }

	// Read request from HTTP client
	HttpHeaders headers;
   while (!headers.is_complete()) {
      char buf[1000];
      int len = read(fd, buf, sizeof(buf)-1);
      if (len == 0) {
         if (optVerbose) {
            printf("proxyPlainClientProc: eof?  len=%d\n", len);
         }
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("proxyPlainClientProc: read error");
         }
         break;
      }
		if (optVerbose > 1) {
			//printf("proxyPlainClientProc: Len:%d  Header: %*.*s\n", len, len, len, buf);
		}
		recvBytes += len;
		headers.add_data(buf, len);
   }

   try {
      if (optVerbose) {
			printf("Header is complete\n");
			if (optVerbose > 1) {
				for (auto &line : headers.headerlines) {
					printf("%s\n", line.c_str());
				}
			}
		   printf("Verb:  %s\n", headers.get_verb().c_str());
		   printf("Proto: %s\n", headers.get_protocol().c_str());
		   printf("File:  %s\n", headers.get_file().c_str());
      }

	   if (headers.get_verb() == "GET") {
		   handle_get(headers.get_file());
	   } else {
		   emit_error(500, "Illegal verb: " + headers.get_verb());
	   }
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      printf("Closing socket %d\n", fd);
   }
   removeClient(fd);
   close(fd);
	fd = -1;
}

void ProxyClient::send(int sd, const void *data_p, unsigned int len)
{
	const char *data = (const char*) data_p;
	unsigned int pos = 0;
	while (pos < len) {
		int ret = write(sd, data + pos, len);
		if (optVerbose) {
			printf("Sending %u bytes on fd=%d  -->  sent %d\n", len, sd, ret);
		}
		if (ret <= 0) {
			return;
		}
		pos += ret;
		len -= ret;
	}
}

void ProxyClient::send(const std::string &hdr, const unsigned char *body, unsigned int body_len)
{
	if (optVerbose) {
		printf("Sending Header: %s\nFollowed by %u bytes body.\n", hdr.c_str(), body_len);
	}

	send(fd, hdr.c_str(), hdr.size());
	send(fd, body, body_len);
}

void ProxyClient::send(const std::string &hdr, const std::string &body)
{
	send(hdr, (const unsigned char *)body.c_str(), body.size());
}

void ProxyClient::emit_error(int code, const std::string &text)
{
	std::string body;
	body += "<html>\r\n";
	body += "Unsupported request<p>\r\n";
	body += "Error code " + std::to_string(code) + "<p>\r\n";
	body += text + "\r\n";
	body += "</html>\r\n";

	std::string hdr;
	hdr += "HTTP/1.1 " + std::to_string(code) + " Error\r\n";
	hdr += "Content-Type: text/html\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(hdr, body);
}

void ProxyClient::handle_get_html(int size)
{
	const std::string source = "Q-Free is a prime mover in the world of smart, safe, and sustainable transportation management. We go to work every day hoping to do two things: improve mobility and make the world a little better. Collectively, we channel our energy to influence and develop the global ITS community. We improve traffic flow, road safety, and air quality in communities all over the world. ";
	std::string body;
	body += "<html>\r\n";
	while ((int)body.size() < size) {
		body += source;
	}
	if ((int)body.size() > size)
		body = body.substr(0, size);
	body += "</html>\r\n";

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: text/html\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(hdr, body);
}

void ProxyClient::handle_get_text(int size)
{
	const std::string source = "Q-Free is a prime mover in the world of smart, safe, and sustainable transportation management.\r\n";
	std::string body;
	while ((int)body.size() < size) {
		body += source;
	}
	if ((int)body.size() > size)
		body = body.substr(0, size);

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: text/plain\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(hdr, body);
}

void ProxyClient::handle_get_bin(int size)
{
	std::vector<unsigned char> body;
	unsigned char ch = 0;
	while ((int)body.size() < size) {
		body.push_back(ch++);
	}

	std::string hdr;
	hdr += "HTTP/1.1 200 OK\r\n";
	hdr += "Content-Type: application/octet-stream\r\n";
	hdr += "Content-Length: " + std::to_string(body.size()) + "\r\n";
	hdr += "\r\n";
	send(hdr, body.data(), body.size());
}

void ProxyClient::handle_get_proxy(ConnectionClient *conn, const std::string &file, const ProxyRule &rule)
{
	bool success = conn->connect(rule.dst_host, rule.dst_port);
	if (!success) {
		printf("Connection error to host %s\n", rule.dst_host.c_str());
		emit_error(500, "Connection error to " + rule.dst_host);
		return;
	}

	printf("GET %s from %s\n", rule.dst_file.c_str(), rule.dst_host.c_str());
	char szHttpRequest[500];
	sprintf(szHttpRequest, "GET %s HTTP/1.1\r\nHost: %s\r\nConnection: close\r\n\r\n", rule.dst_file.c_str(), rule.dst_host.c_str());
	conn->send(szHttpRequest, strlen(szHttpRequest));

	std::vector<unsigned char> body;
	HttpHeaders headers;
   while (!headers.is_complete()) {
      unsigned char buf[1000];
      int len = conn->recv(buf, sizeof(buf)-1);
      if (len == 0) {
         if (optVerbose) {
            printf("handle_get_proxy: eof?  len=%d\n", len);
         }
         break;
      }
      if (len < 0) {
         if (optVerbose) {
            perror("handle_get_proxy: read error");
         }
         break;
      }
		if (optVerbose > 1) {
			printf("handle_get_proxy: Len:%d bytes read from %s\n", len, rule.dst_host.c_str());
			// printf("handle_get_proxy: Len:%d  Header: %*.*s\n", len, len, len, (char*)buf);
			// printf("%s\n", bin2hex(buf, len));
		}
		recvBytes += len;
		body = headers.add_data((char*)buf, len);
   }

   try {
      if (optVerbose) {
			printf("handle_get_proxy.Header is complete\n");
			if (optVerbose > 1) {
				for (auto &line : headers.headerlines) {
					printf("%s\n", line.c_str());
				}
			}
			printf("handle_get_proxy.Body has %d bytes (so far)\n", (int) body.size());
			printf("%s\n", bin2hex(body.data(), (unsigned int)body.size()));
      }
		int contLen = headers.get_content_length();
      if (optVerbose) {
			printf("ContentLength: %d\n", contLen);
		}

		// Send header lines to client
		for (auto &h : headers.headerlines) {
			send(fd, (h + "\r\n").c_str(), h.size() + 2);
		}
		send(fd, body.data(), body.size());
		contLen -= body.size();

		while (contLen) {
			unsigned char buf[1000];
			int len = conn->recv(buf, sizeof(buf)-1);
			if (len == 0) {
				if (optVerbose) {
					printf("handle_get_proxy: eof?  len=%d\n", len);
				}
				break;
			}
			if (len < 0) {
				if (optVerbose) {
					perror("handle_get_proxy: read error");
				}
				break;
			}
			if (optVerbose > 1) {
				printf("handle_get_proxy: Body: Len:%d\n", len);
				// printf("%s\n", bin2hex(buf, len));
			}
			send(fd, buf, len);
			contLen -= len;
		}
   } catch (const char *msg) {
      printf("Catched exception: %s\n", msg);
   }

   if (optVerbose) {
      printf("Closing connection to %s\n", rule.dst_host.c_str());
   }
   conn->close();
}

void ProxyClient::handle_get(const std::string &file)
{
	if (optVerbose) {
		printf("Handle get: %s\n", file.c_str());
	}

	// Check if this as an proxy alias
	for (auto &r : rules) {
		if (file.find(r.src_file) == 0) {
			printf("Proxy rule match: %s --> %s:%d%s\n", r.src_file.c_str(), r.dst_host.c_str(), r.dst_port, r.dst_file.c_str());
			ConnectionClient *conn = 0;
			if (r.dst_https)
				conn = new ConnectionClientTls;
			else
				conn = new ConnectionClientTcp;
			
			handle_get_proxy(conn, file, r);
			delete conn;
			conn = 0;
			return;
		}
	}
	
	int size, cnt;

	// Request HTML file of abritary length
	cnt = sscanf(file.c_str(), "/%d.html", &size);
	if (cnt == 1 && file.find(".html") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_html(size);
		return;
	}

	// Request plain text file of abritary length
	cnt = sscanf(file.c_str(), "/%d.text", &size);
	if (cnt == 1 && file.find(".text") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_text(size);
		return;
	}

	// Request binary file of abritary length
	cnt = sscanf(file.c_str(), "/%d.bin", &size);
	if (cnt == 1 && file.find(".bin") != std::string::npos && size > 0) {
		if (size < 100) size = 100;
		if (size > 1000000) size = 1000000;
		handle_get_bin(size);
		return;
	}

	// No match: error
	emit_error(400, "Illegal URL");
}
