
/* ROOT SERVER */
const char *rootServers[] = {
	"198.41.0.4",		//a.root-servers.net.	
	"192.228.79.201",	//b.root-servers.net.
	"192.33.4.12", 		//c.root-servers.net.
	"199.7.91.13",		//d.root-servers.net.
	"192.203.230.10",	//e.root-servers.net.
	"192.5.5.241",		//f.root-servers.net.
	"192.112.36.4",		//g.root-servers.net.
	"128.63.2.53",		//h.root-servers.net.
	"192.36.148.17",	//i.root-servers.net.
	"192.58.128.30",	//j.root-servers.net.
	"199.7.83.42",		//l.root-servers.net.
	"202.12.27.33",		//m.root-servers.net.
	"193.0.14.129"		//k.root-servers.net.
};

#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include <vector>
#include <string>

#include "dns_messages.h"

using namespace std;

class Resolver {
public:
	

	int resolve(vector<ResRecord> &RRs, std::vector<std::string> &nServers, const char* dName, short qType = 1);
	int resolve(const char* nsIP, const char* dName, short qType = 1);
	
	
	void initRoot(std::vector<std::string> &nServers);
	void getAuthorities(std::vector<std::string> &authServers);
	void getAuthorityAnswer(vector<ResRecord> &RRs);
	
	const char* getBuf() { return buf; }
private:
	//Query/Response buffer
	char buf[4096];
	//Name Servers, Inited with root servers
	vector<std::string> nServers;
};
