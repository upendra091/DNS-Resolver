#include <cstring>
#include <cstdio>
#include <string>
#include<sys/socket.h>    
#include<arpa/inet.h> 
#include<netinet/in.h>
#include <iostream>	
#include <iomanip>	
#include <sstream>  

#include <ctime>

#define T_A	1	//IPV4			
#define T_NS	2			
#define T_CNAME	5	//the canonical name
#define T_AAAA	28	//IPV6
#define T_OPT	41	//OPT
#define T_RRSIG 46	//RRSIG

using namespace std;

class Header {
public:
	void init();
	
	unsigned char getErrCode() const { return rCode; }
	bool isAuthoritative() const  { return aa; }
	
	//Answer RRs count
	unsigned short getAnCount() const { return ntohs(anCount); }
	
	//Authority RRs count
	unsigned short getAuthCount() const { return ntohs(nsCount); }
	
	//Additional RRs count
	unsigned short getAdCount() const { return ntohs(arCount); }
	
private:
    unsigned short id;				// A 16 bit identifier assigned by the program

    unsigned char rd :1;			
    unsigned char tc :1;			
    unsigned char aa :1;			// Authoritative Answer
    unsigned char opCode :4;			// kind of query in this message
    unsigned char qr :1;			// message is a query (0), or a response (1).
 
    unsigned char rCode :4;			// Response code
    unsigned char cd :1;			// checking disabled
    unsigned char ad :1;			// authentic data
    unsigned char z :1;				
    unsigned char ra :1;			// Recursion Available
 
    unsigned short qdCount;		// number of entries in the question section.
    unsigned short anCount;		// number of resource records in the answer section.
    unsigned short nsCount;		// number of name server resource records in the authority records
    unsigned short arCount;		// number of resource records in the additional records section
};

class QFixed {
public:
	void set(short type);
private:
	short qType;	// type of the query
	short qClass;	// class of the query
};

class Question {
public:
	Question(char* buf, const char* dName, short qType);
	Question(const char* buf);

	size_t getLen() const;

private:
	const char 	 *qName;	
	QFixed *qFixed;	// Question fixed part
};


//We do not need padding
#pragma pack(push, 1)
class ResRecordFixed {
public:
	short 	type;			
	short 	rrClass;			
	unsigned int 	ttl;		// a 32 bit unsigned integer that specifies the time to live
	unsigned short 	rdLength;	// an unsigned 16 bit integer that specifies the length in octets of the RDATA field
};
#pragma pack(pop)

class ResRecord {
public:
	ResRecord(const char* buf);
	ResRecord(char* buf, char qName, char qRData);
	
	//Return total len (fixed + dynamic)
	size_t getLen() const;
	
	short getType() const;
	unsigned int getTtl() const;
	unsigned short getRdLen() const;
	const char* getRData() const { return rData; }

private:
	const char *name;	
	const ResRecordFixed  *resRF; 
protected:
	const char *rData;	
};



class DomainName : public ResRecord {
public:
	static int  dNameToLabels(char* out, const char* in);
	static void labelsToDname(string &out, const char* dName);

	/* RFC 1035: 4.1.4. Message compression */
	static int uncompress(char* out, const char* dName, const char* buf);
	//Return compressed length
	static int getLen(const char* dName);
	

	string getDName(const char* buf) {
			string dName;
			char labels[255];
			uncompress(labels, rData, buf);
			labelsToDname(dName, labels);
			
			return dName;
	}
private:
};


class IP4Type : public ResRecord {
public:
	string getFormatedString() {
		std::stringstream ss;

	  ss << left << setw(8) << getTtl() << " IN      A       " << getIP();
	  return ss.str();
	}

	string getIP() {
		struct sockaddr_in a;
		a.sin_addr.s_addr = *((long*)rData);
		
		return 	inet_ntoa(a.sin_addr);
	}
};

class IP6Type : public ResRecord {
public:
	string getFormatedString() {
		std::stringstream ss;

	  ss << left << setw(8) << getTtl() << " IN      AAAA    " << getIP();

		return ss.str();
	}

	string getIP() {
			struct sockaddr_in6 addr;
			char straddr[INET6_ADDRSTRLEN];
			
			memset(&addr, 0, sizeof(addr));
			addr.sin6_family = AF_INET6;

			for(int x = 0; x < getRdLen(); ++x)
				addr.sin6_addr.s6_addr[x] = rData[x];
			
			return inet_ntop(AF_INET6, &addr.sin6_addr, straddr, sizeof(straddr));
	}
};

class CNameType : public DomainName {
public:
	string getFormatedString() {
		std::stringstream ss;

	  ss << left << setw(8) << getTtl() << " IN      CNAME   ";

		return ss.str();
	}
};

#include<stdlib.h>    //malloc
static char encoding_table[] = {'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
                                'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
                                'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
                                'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
                                'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
                                'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
                                'w', 'x', 'y', 'z', '0', '1', '2', '3',
                                '4', '5', '6', '7', '8', '9', '+', '/'};
static int mod_table[] = {0, 2, 1};



#pragma pack(push, 1)
class RRSIG {
public:
    unsigned short type_covered;
    unsigned char  algorithm;
    unsigned char  labels;
    unsigned int   original_ttl;
    unsigned int   signature_expiration;
    unsigned int   signature_inception;
    unsigned short key_tag;
};
#pragma pack(pop)

/*RFC 4034: 3.2.  The RRSIG RR Presentation Format */

class RRSIGType : public ResRecord {
public:
	string getFormatedString() const {
		std::stringstream ss;
		
		RRSIG *rrsig = (RRSIG*)rData;

	  ss << left << setw(8) << getTtl() << " IN      RRSIG  "
			 << " " << ((ntohs(rrsig->type_covered) == T_A) ? "A" : "AAAA")
			 << " " << (int)rrsig->algorithm
			 << " " << (int)rrsig->labels
			 << " " << ntohl(rrsig->original_ttl)
			 << " " << geTimeDigFormat(ntohl(rrsig->signature_expiration))
			 << " " << geTimeDigFormat(ntohl(rrsig->signature_inception))
			 << " " << ntohs(rrsig->key_tag);
			
		
		//Advance to Signer's Name
		const char* localBuf = rData + sizeof(RRSIG);
		
		string cName;
		DomainName::labelsToDname(cName, localBuf);
		ss << " " << cName;
		
		size_t signatureLen = getRdLen() - sizeof(RRSIG) - DomainName::getLen(localBuf);
		
		size_t output_length;
		
		localBuf += DomainName::getLen(localBuf);
		char *rrsigB64 = base64_encode((const unsigned char *)localBuf, signatureLen, &output_length);
		ss << " " << rrsigB64;

		if(rrsigB64)
			free(rrsigB64);

		return ss.str();
	}
	
	string geTimeDigFormat(const unsigned int eTime) const {
		time_t epoch = eTime;
		struct tm *date = gmtime(&epoch);
		
		std::stringstream ss;
		ss << date->tm_year + 1900 << date->tm_mon + 1 << date->tm_mday << date->tm_hour << date->tm_min << date->tm_sec;
		
		return ss.str();
	}
	
private:
	
	char *base64_encode(const unsigned char *data,
	                    size_t input_length,
	                    size_t *output_length) const {
	
	    *output_length = 4 * ((input_length + 2) / 3);
	
	    char *encoded_data = (char*)malloc(*output_length);
	    if (encoded_data == NULL) return NULL;
	
	    for (int i = 0, j = 0; i < input_length;) {
	
	        uint32_t octet_a = i < input_length ? (unsigned char)data[i++] : 0;
	        uint32_t octet_b = i < input_length ? (unsigned char)data[i++] : 0;
	        uint32_t octet_c = i < input_length ? (unsigned char)data[i++] : 0;
	
	        uint32_t triple = (octet_a << 0x10) + (octet_b << 0x08) + octet_c;
	
	        encoded_data[j++] = encoding_table[(triple >> 3 * 6) & 0x3F];
	        encoded_data[j++] = encoding_table[(triple >> 2 * 6) & 0x3F];
	        encoded_data[j++] = encoding_table[(triple >> 1 * 6) & 0x3F];
	        encoded_data[j++] = encoding_table[(triple >> 0 * 6) & 0x3F];
	    }
	
	    for (int i = 0; i < mod_table[input_length % 3]; i++)
	        encoded_data[*output_length - 1 - i] = '=';
	
	    return encoded_data;
	}
};
