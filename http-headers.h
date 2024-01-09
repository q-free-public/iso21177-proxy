// http-headers.h
//
// This file is identical in projects:
//   cits-lte-catm1-test
//   cits-iso21177-proxy
//   cits-iso21177-automotive
//

#include <string>
#include <list>
#include <vector>

class HttpHeaders {
public:
    HttpHeaders() {
        clear();
    }

	std::vector<unsigned char> add_data(const char *buf, int len) {
		for (int i=0; i<len; i++) {
			if (buf[i] == '\n') {
                // printf("Hdr: EOL '%s'  empty:%d\n", line.c_str(), line.empty());
				if (line.empty()) {
                    hdr_is_complete = true;
					return std::vector<unsigned char>(buf + i + 1, buf + len);
                }
				headerlines.push_back(line);
				line.clear();
			} else if (buf[i] == '\r') {
				// ignore
			} else {
				line += buf[i];
			}
		}
		
		return std::vector<unsigned char>();
	}

	void clear() {
		headerlines.clear();
		line.clear();
        hdr_is_complete = false;
	}

	bool is_complete() {
		return (!headerlines.empty() && hdr_is_complete);
	}

	bool iequals(const std::string& a, const std::string& b)
	{
		return std::equal(a.begin(), a.end(), b.begin(), b.end(), [](char a, char b) { return tolower(a) == tolower(b); });
	}

	std::string get_request_verb() {
		if (!is_complete()) throw "Header is not complete";
		std::vector<std::string> parts = split_on_space(headerlines.front());
		if (parts.size() != 3) throw "First header line does not have 3 components";

		return parts[0];
	}

	std::string get_request_file() {
		if (!is_complete()) throw "Header is not complete";
		std::vector<std::string> parts = split_on_space(headerlines.front());
		if (parts.size() != 3) throw "First header line does not have 3 components";

		std::string filename = parts[1];
		while (true) {
			std::string::size_type pos = filename.find("%20");
			if (pos == std::string::npos)
				break;
			filename = filename.replace(pos, 3, " ");
		}
		return filename;
	}

	std::string get_request_protocol() {
		if (!is_complete()) throw "Header is not complete";
		std::vector<std::string> parts = split_on_space(headerlines.front());
		if (parts.size() != 3) throw "First header line does not have 3 components";

		return parts[2];
	}

	std::string get_reply_protocol() {
		if (!is_complete()) throw "Header is not complete";
		std::vector<std::string> parts = split_on_space(headerlines.front());
		if (parts.size() < 2) throw "First header line does not have 2 or more components";

		return parts[0];
	}

	int get_reply_status() {
		if (!is_complete()) throw "Header is not complete";
		std::vector<std::string> parts = split_on_space(headerlines.front());
		if (parts.size() < 2) throw "First header line does not have 2 or more components";

		return stoi(parts[1]);
	}

	int get_content_length()
	{
		const std::string tag("Content-Length:");
		for (auto &h : headerlines) {
			if (iequals(tag, h.substr(0, tag.size()))) {
				int len = std::stoi(h.substr(tag.size()));
				return len;
			}
		}
		return -1;
	}

	std::string get_content_type()
	{
		const std::string tag("Content-Type:");
		for (auto &h : headerlines) {
			if (iequals(tag, h.substr(0, tag.size()))) {
				unsigned int pos = tag.size();
				while (pos < h.size() && h[pos] == ' ') pos++;
				return h.substr(pos);
			}
		}
		return "";
	}
	
	std::vector<std::string> split_on_space(const std::string &str)
	{
		return split(str, " ");
	}

	std::vector<std::string> split(const std::string &str, const std::string &delims)
	{
		std::vector<std::string> parts;
		for (unsigned int i=0; i<str.size(); i++) {
			unsigned int start = i;
			while (i<str.size() && delims.find(str[i]) == std::string::npos) i++;
			parts.push_back(str.substr(start, i-start));
		}

		return parts;
	}

	std::list<std::string> headerlines;
	std::string line;
    bool hdr_is_complete;
};
