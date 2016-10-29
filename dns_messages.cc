#include "dns_messages.h"

#include <iostream>
#include<arpa/inet.h>
#include <cstdlib>
#include <iostream>	

void Header::init() 
{
	id = htons(123);	
	qr = 0; 					// This is a query
	opCode = 0;				
	aa = 0;					
	tc = 0; 					
	rd = 0; 				
	ra = 0; 					
	z = 0;
	ad = 0;
	cd = 0;
	rCode = 0;
	qdCount = htons(1); //we have only 1 question
	anCount = 0;
	nsCount = 0;
	arCount = htons(1);	// EDNS 1 additional record (OPT)
}

void QFixed::set(short type) {
	qType  = htons(type);
	qClass = htons(1); //always IN class
}

Question::Question(char* buf, const char* dName, short qType) {
	size_t qNameLen = DomainName::dNameToLabels(buf, dName);

	qName = buf;

	qFixed = (QFixed *)&buf[qNameLen];

	qFixed->set(qType);
}

Question::Question(const char* buf) {
	qName = buf;
	

	size_t qNameLen = DomainName::getLen(qName);


}

size_t Question::getLen() const {
	int len = DomainName::getLen(qName);

	return len + sizeof(QFixed);
}

ResRecord::ResRecord(const char* buf) {
	name  = buf;
	
	// name comressed length
	int len = DomainName::getLen(name);
	
	//Advance the buffer to Resource record fixed part
	buf += len;
	resRF = (ResRecordFixed*)buf;
	
	//Advance the buffer to RDATA
	buf += sizeof(ResRecordFixed);
	rData = buf;
}


ResRecord::ResRecord(char* buf, char qName, char qRData) {
	*buf = qName;
	name  = buf;
	
	buf += 1;	//Empty name just '\0'
	
	((ResRecordFixed*) buf)->type = htons(41);
	((ResRecordFixed*) buf)->rrClass = htons(4096);
	((ResRecordFixed*) buf)->ttl = htonl(0x8000);
	((ResRecordFixed*) buf)->rdLength = 0;
	
	resRF = (const ResRecordFixed*)buf;

	//Advance the buffer to RDATA
	buf += sizeof(ResRecordFixed);
	*buf = qRData;
	rData = buf;
	
}

size_t ResRecord::getLen() const {
	int len = DomainName::getLen(name);

	return len	//Compressed domain name len
				+ sizeof(ResRecordFixed)	
				+ getRdLen();	//RDATA len
}

short ResRecord::getType() const {
	return ntohs(resRF->type);
}

unsigned int ResRecord::getTtl() const {
	return ntohl(resRF->ttl);
}


unsigned short ResRecord::getRdLen() const {
	return ntohs(resRF->rdLength);
}

int DomainName::dNameToLabels(char* outOr, const char* in) {
	char* out = outOr;
	
		if( !out || !in )
		return 0;

  const char *lastFound = in;
  const char *pch;
  unsigned char labelLen;
  size_t outLen = 0;

  pch = strchr(in, '.');
  while (pch != NULL)
	{
  	labelLen = pch-lastFound;
    outLen += labelLen + 1;

		*out++ = (char)(labelLen);
    memcpy(out, lastFound, labelLen);
    out += labelLen;
    
  	lastFound = pch+1;
    pch = strchr(pch+1, '.');
  }
  
  pch = strchr(in, '\0');
  labelLen = pch-lastFound;
  
  if(labelLen != 0)
	{
	  outLen += labelLen + 1;

		*out++ = (char)(labelLen);
    memcpy(out, lastFound, labelLen);
    out += labelLen;
	}
	
	//Add null to terminate the string
	*out = 0;
	++outLen;
	
	return outLen;
}

/* @dName uncompressed Domain Name */
void DomainName::labelsToDname(string &out, const char* dName) {
	size_t inLen = strlen(dName);
	for(size_t i = 0; i < inLen; ++i) 
	{
	    size_t labelLen = dName[i];
	    for(size_t j = 0; j < labelLen; ++j) 
	    	out += dName[++i];

	    out += '.';
	}
}

int DomainName::uncompress(char *out, const char* dName, const char* buf) {
	int  len = 0;
	const unsigned char *c = (const unsigned char *)dName;

	do {
		if(*c >> 6 == 3) {
			size_t offset = ((unsigned short)(*c & 0x3F) << 8) | (unsigned short)c[1];
			c = (const unsigned char *)&buf[offset];
		}
	 	out[len++] = *c;

	} while(*c++ != 0);
	
	return len;
}

int DomainName::getLen(const char* dName) {
	int  len = 0;
	const unsigned char *c = (const unsigned char *)dName;

	do {
		++len;
		if(*c >> 6 == 3) {
			++len;
			break;
		}
	} while(*c++ != 0);
	
	return len;
}
