#include "myresolver.h"
#include <cstdlib>
#include <iostream>	
#include <iomanip>	

int main(int argc, char *argv[]) {

	short qType;

	if(argc == 2) {
		qType = T_A;
	} else if (argc == 3) {
		if(strcmp(argv[2], "A") == 0)
			qType = T_A;
		else if(strcmp(argv[2], "AAAA") == 0)
			qType = T_AAAA;
		else {
			cerr << argv[0] << "<Domain Name> [A/AAAA]" << endl;
			exit(-1);
		}
	}
	
	char dName[255];
	memcpy(dName, argv[1], strlen(argv[1])+1);
	
	bool isCName;
	
	do {
		isCName = false;

		vector<ResRecord> RRs;
		vector<string> nServers;
		Resolver resolver;
		resolver.initRoot(nServers);
		int ret = resolver.resolve(RRs, nServers, dName, qType);
	
		/* the domain name exists, but no A or AAAA record(s) 
		   are associated with the domain name */
		
		if(ret == 1) {
			cerr << dName << " may not exist (NXDOMAIN)." << endl;
		} else if(RRs.empty()) {
			cout << dName << " exists, but no " << ((qType == T_A) ? "A" : "AAAA") << " record(s) are associated with the domain name." << endl;
		/* the original domain name resolves to a CNAME or chain of CNAMEs which 
			 must each be resolved to obtain a final answer */
		} else if ( RRs[0].getType() == T_CNAME) {
			//Redo all with new nsName as Cname and root servers
			
			string cName;
			char cNameLabels[255];
			DomainName::uncompress(cNameLabels, RRs[0].getRData(), resolver.getBuf());
			DomainName::labelsToDname(cName, cNameLabels);
			CNameType *a = static_cast<CNameType*>(&RRs[0]);
			
			cout << left << setw(25) << dName
					 << a->getFormatedString()
					 << cName
					 << endl;
	
			memcpy(dName, cName.c_str(), cName.size() + 1);

			isCName = true;
			
		} else {
			for(int ai = 0; ai < RRs.size(); ++ai) {
				if( RRs[ai].getType() == T_A ) {
					IP4Type *a = static_cast<IP4Type*>(&RRs[ai]);
					
					cout << left << setw(25) << dName
							 << a->getFormatedString() << endl;
				}
				else if( RRs[ai].getType() == T_RRSIG ) {
					RRSIGType *a = static_cast<RRSIGType*>(&RRs[ai]);
					
					cout << left << setw(25) << dName
							 << a->getFormatedString() << endl;
				}
				else if( RRs[ai].getType() == T_AAAA ) {
					IP6Type *a = static_cast<IP6Type*>(&RRs[ai]);
					
					cout << left << setw(25) << dName
							 << a->getFormatedString() << endl;
				}
			}
		}
	} while(isCName);

	return 0;
}

int Resolver::resolve(vector<ResRecord> &RRs, std::vector<std::string> &nServers, const char* dName, short qType) {
	for( int i = 0; i < nServers.size(); i++ ) {
		const char *nsIP = nServers[i].c_str();

		int ret = resolve(nsIP, dName, qType);
		if( ret != -1 ) {
			if(ret == 0) {
				getAuthorityAnswer(RRs);
			} else if(ret == 2) {
				std::vector<std::string> authServers;
				getAuthorities(authServers);

				Resolver resolver;
				return resolver.resolve(RRs, authServers, dName, qType);
			}
			
			return ret;
		}
	}
	
	return -1;
}


int Resolver::resolve(const char* nsIP, const char* dName, short qType) {
	//Name Server UDP socket
	int nsSocket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	
	/* 3s Timeout */
	struct timeval tv;
	tv.tv_sec = 3;
	tv.tv_usec = 0;
	if (setsockopt(nsSocket, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv)) < 0)
		perror("setsockopt: ");
	
	//Name Server Internet Socket Address
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port 	= htons(53); //DNS port

	//Name Server IP address
	dest.sin_addr.s_addr = inet_addr(nsIP);

	memset(buf, 0, 4096);
	
	//Construct the DNS header on the buffer
	Header *qHeader = (Header *)buf;
	//Init the buffer with default values (No recursion, 1 Query, ...)
	qHeader->init();

	//Construct the question on the buffer, with query data (Domain name & (A|AAAA) & default class)
	Question question(&buf[sizeof(Header)], dName, qType);

	//EDNS opt
	ResRecord opt(&buf[sizeof(Header) + question.getLen()], '\0', '\0');

	const size_t queryLen = sizeof(Header) + question.getLen() + opt.getLen();

	//Send query
  if(sendto(nsSocket, buf, queryLen, 0, (struct sockaddr*)&dest, sizeof(dest)) < 0) {
    perror("sendto: ");
    //close(nsSocket);
    return -1;
  }
  
  //Receive answer
  int i = sizeof dest;
  //printf("\nReceiving answer...\n");
  if(recvfrom(nsSocket, buf, 4096, 0, (struct sockaddr*)&dest, (socklen_t*)&i) < 0) {
    perror("recvfrom: ");
    //close(nsSocket);
    return -1;
  }
	
	
	Header *rHeader = (Header *)buf;

	if(rHeader->getErrCode() == 1 || rHeader->getErrCode() == 4 || rHeader->getErrCode() == 5) {
  	return -1;
  }

	
  if(rHeader->getErrCode() == 2)
  	return -1;
  
  /* Authoritative */
  if(rHeader->isAuthoritative()) {
  	/* NXDOMAIN */
		if(rHeader->getErrCode() == 3)
			return 1;
		
		else
			return 0;
	/* non Authoritative */
	} else if (rHeader->getErrCode() == 0) {
		return 2;
	}

	return -1;
}

void Resolver::initRoot(vector<string> &nServers) {
	nServers.clear();
	nServers.insert(nServers.begin(), rootServers, rootServers + sizeof(rootServers) / sizeof(rootServers[0]));

}


void Resolver::getAuthorities(vector<string> &authServers) {
	const char* localBuffer = buf;

	//Construct the DNS header from the buffer
	const Header *rHeader = (const Header *)localBuffer;

	//Advance to the Question section
	localBuffer += sizeof(Header);
	
	//Construct the question from the buffer
	Question question(localBuffer);

	localBuffer += question.getLen();

	unsigned short adCount = rHeader->getAdCount();

	unsigned short authCount = rHeader->getAuthCount();
	

	for(int i = 0; i < authCount; ++i ) {
		ResRecord rr = ResRecord(localBuffer);
		
		if(adCount == 1) {
			if(rr.getType() != T_NS)
				continue;

			vector<ResRecord> RRs;
			std::vector<std::string> nServers;
			
			Resolver::initRoot(nServers);

			DomainName *a = static_cast<DomainName*>(&rr);
			string cppDname = a->getDName(buf);
			
			char dName[255];
			memcpy(dName, cppDname.c_str(), cppDname.size() + 1);

			Resolver resolver;
			resolver.resolve(RRs, nServers, dName);

			for(int ai = 0; ai < RRs.size(); ++ai) {
				if( RRs[ai].getType() == T_A ) {
					IP4Type *a = static_cast<IP4Type*>(&RRs[ai]);

					authServers.push_back(a->getIP());
				}
			}
		}
		localBuffer += rr.getLen();
	}

	
	for(int i = 0; i < adCount; ++i ) {
		ResRecord rr = ResRecord(localBuffer);

		if(rr.getType() == T_A) {
			IP4Type *a = static_cast<IP4Type*>(&rr);
			authServers.push_back(a->getIP());
		}

		localBuffer += rr.getLen();
	}
}

void Resolver::getAuthorityAnswer(vector<ResRecord> &RRs) {
	char* localBuffer = buf;

	//Construct the DNS header from the buffer
	Header *rHeader = (Header *)localBuffer;

	//Advance to the Question section
	localBuffer += sizeof(Header);
	
	//Construct the question from the buffer
	Question question((char*)localBuffer);

	//Advance to the Answer section
	localBuffer += question.getLen();
	
	unsigned short anCount = rHeader->getAnCount();

	//Advance to the Additional section
	for(int i = 0; i < anCount; ++i ) {
		ResRecord rr = ResRecord(localBuffer);
		RRs.push_back(rr);
		
		localBuffer += rr.getLen();
	}
}



