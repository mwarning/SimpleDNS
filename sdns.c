#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>

#define BUF_SIZE 1500

/*
* This software is licensed under the Public Domain.
*
* This is a _basic_ DNS Server for educational use.
*  It doesn't prevent invalid packets from crashing
*  the server.
*
* To test start the program and issue a DNS request:
*  dig @127.0.0.1 -p 9000 foo.bar.com 
*/


typedef unsigned char uchar;
typedef unsigned short ushort;
typedef unsigned int uint;
typedef unsigned long ulong;

/*
* Masks and constants.
*/

static const uint QR_MASK = 0x8000;
static const uint OPCODE_MASK = 0x7800;
static const uint AA_MASK = 0x0400;
static const uint TC_MASK = 0x0200;
static const uint RD_MASK = 0x0100;
static const uint RA_MASK = 0x8000;
static const uint RCODE_MASK = 0x000F;

/* Response Type */
enum {
	Ok_ResponseType = 0,
	FormatError_ResponseType = 1,
	ServerFailure_ResponseType = 2,
	NameError_ResponseType = 3,
	NotImplemented_ResponseType = 4,
	Refused_ResponseType = 5
};

/* Resource Record Types */
enum {
	A_Resource_RecordType = 1,
	NS_Resource_RecordType = 2,
	CNAME_Resource_RecordType = 5,
	SOA_Resource_RecordType = 6,
	PTR_Resource_RecordType = 12,
	MX_Resource_RecordType = 15,
	TXT_Resource_RecordType = 16,
	AAAA_Resource_RecordType = 28,
	SRV_Resource_RecordType = 33
};

/* Operation Code */
enum {
	QUERY_OperationCode = 0, /* standard query */
	IQUERY_OperationCode = 1, /* inverse query */
	STATUS_OperationCode = 2, /* server status request */
	NOTIFY_OperationCode = 4, /* request zone transfer */
	UPDATE_OperationCode = 5 /* change resource records */
};

/* Response Code */
enum {
	NoError_ResponseCode = 0,
	FormatError_ResponseCode = 1,
	ServerFailure_ResponseCode = 2,
	NameError_ResponseCode = 3
};

/* Query Type */
enum {
	IXFR_QueryType = 251,
	AXFR_QueryType = 252,
	MAILB_QueryType = 253,
	MAILA_QueryType = 254,
	STAR_QueryType = 255
};

/*
* Types.
*/

/* Question Section */
struct Question {
	char *qName;
	ushort qType;
	ushort qClass;
	struct Question* next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData {
	struct {
		char *txt_data;
	} txt_record;
	struct {
		uchar addr[4];
	} a_record;
	struct {
		char* MName;
		char* RName;
		uint serial;
		uint refresh;
		uint retry;
		uint expire;
		uint minimum;
	} soa_record;
	struct {
		char *name;
	} name_server_record;
	struct {
		char name;
	} cname_record;
	struct {
		char *name;
	} ptr_record;
	struct {
		ushort preference;
		char *exchange;
	} mx_record;
	struct {
		uchar addr[16];
	} aaaa_record;
	struct {
		ushort priority;
		ushort weight;
		ushort port;
		char *target;
	} srv_record;
};

/* Resource Record Section */
struct ResourceRecord {
	char *name;
	ushort type;
	ushort class;
	ushort ttl;
	ushort rd_length;
	union ResourceData rd_data;
	struct ResourceRecord* next; // for linked list
};

struct Message {
	ushort id; /* Identifier */

	/* Flags */
	ushort qr; /* Query/Response Flag */
	ushort opcode; /* Operation Code */
	ushort aa; /* Authoritative Answer Flag */
	ushort tc; /* Truncation Flag */
	ushort rd; /* Recursion Desired */
	ushort ra; /* Recursion Available */
	ushort rcode; /* Response Code */

	ushort qdCount; /* Question Count */
	ushort anCount; /* Answer Record Count */
	ushort nsCount; /* Authority Record Count */
	ushort arCount; /* Additional Record Count */

	/* At least one question; questions are copied to the response 1:1 */
	struct Question* questions;

	/*
	* Resource records to be send back.
	* Every resource record can be in any of the following places.
	* But every place has a different semantic.
	*/
	struct ResourceRecord* answers;
	struct ResourceRecord* authorities;
	struct ResourceRecord* additionals;
};

int get_A_Record(uchar addr[4], const char domain_name[])
{
	if(strcmp("foo.bar.com", domain_name) == 0)
	{
		addr[0] = 192;
		addr[1] = 168;
		addr[2] = 1;
		addr[3] = 1;
		return 0;
	}
	else
	{
		return -1;
	}
}

int get_AAAA_Record(uchar addr[16], const char domain_name[])
{
	if(strcmp("foo.bar.com", domain_name) == 0)
	{
		addr[0] = 0xfe;
		addr[1] = 0x80;
		addr[2] = 0x00;
		addr[3] = 0x00;
		addr[4] = 0x00;
		addr[5] = 0x00;
		addr[6] = 0x00;
		addr[7] = 0x00;
		addr[8] = 0x00;
		addr[9] = 0x00;
		addr[10] = 0x00;
		addr[11] = 0x00;
		addr[12] = 0x00;
		addr[13] = 0x00;
		addr[14] = 0x00;
		addr[15] = 0x00;
		return 0;
	}
	else
	{
		return -1;
	}
}


/*
* Debugging functions.
*/

void print_hex(uchar* buf, size_t len)
{
	int i;
	printf("%u bytes:\n", len);
	for(i = 0; i < len; ++i)
		printf("%02x ", buf[i]);
	printf("\n");
}

void print_resource_record(struct ResourceRecord* rr)
{
	int i;
	while(rr)
	{
		printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
				rr->name,
				rr->type,
				rr->class,
				rr->ttl,
				rr->rd_length
		);

		union ResourceData *rd = &rr->rd_data;
		switch(rr->type)
		{
			case A_Resource_RecordType:
				printf("Address Resource Record { address ");
			
				for(i = 0; i < 4; ++i)
					printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);
			
				printf(" }");
				break;
			case NS_Resource_RecordType:
				printf("Name Server Resource Record { name %u}",
					rd->name_server_record.name
				);
				break;
			case CNAME_Resource_RecordType:
				printf("Canonical Name Resource Record { name %u}",
					rd->cname_record.name
				);
				break;
			case SOA_Resource_RecordType:
				printf("SOA { MName '%s', RName '%s', serial %u, refresh %u, retry %u, expire %u, minimum %u }",
					rd->soa_record.MName,
					rd->soa_record.RName,
					rd->soa_record.serial,
					rd->soa_record.refresh,
					rd->soa_record.retry,
					rd->soa_record.expire,
					rd->soa_record.minimum
				);
				break;
			case PTR_Resource_RecordType:
				printf("Pointer Resource Record { name '%s' }",
					rd->ptr_record.name
				);
				break;
			case MX_Resource_RecordType:
				printf("Mail Exchange Record { preference %u, exchange '%s' }",
					rd->mx_record.preference,
					rd->mx_record.exchange
				);
				break;
			case TXT_Resource_RecordType:
				printf("Text Resource Record { txt_data '%s' }",
					rd->txt_record.txt_data
				);
				break;
			case AAAA_Resource_RecordType:
				printf("AAAA Resource Record { address ");
			
				for(i = 0; i < 16; ++i)
					printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);
			
				printf(" }");
				break;
			default:
				printf("Unknown Resource Record { ??? }");
		}
		printf("}\n");
		rr = rr->next;
	}
}

void print_query(struct Message* msg)
{
	printf("QUERY { ID: %02x", msg->id);
	printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->qr, msg->opcode);
	printf(", QDcount: %u", msg->qdCount);
	printf(", ANcount: %u", msg->anCount);
	printf(", NScount: %u", msg->nsCount);
	printf(", ARcount: %u,\n", msg->arCount);

	struct Question* q = msg->questions;
	while(q)
	{
		printf("  Question { qName '%s', qType %u, qClass %u }\n",
			q->qName,
			q->qType,
			q->qClass
		);
		q = q->next;
	}

	print_resource_record(msg->answers);
	print_resource_record(msg->authorities);
	print_resource_record(msg->additionals);

	printf("}\n");
}


/*
* Basic memory operations.
*/

size_t get16bits(const uchar** buffer)
{
	ushort value;

	value = ntohs( *((typeof(value)*) *buffer) );
	*buffer += 2;

	return value;
}

void put8bits(uchar** buffer, uchar value)
{
	*((typeof(value)*) *buffer) = value;
	*buffer += 1;
}

void put16bits(uchar** buffer, ushort value)
{
	*((typeof(value)*) *buffer) = htons( value );
	*buffer += 2;
}

void put32bits(uchar** buffer, unsigned long long value)
{
	*((typeof(value)*) *buffer) = htonl( value );
	*buffer += 4;
}

/*
* Deconding/Encoding functions.
*/

// 3foo3bar3com0 => foo.bar.com
char* decode_domain_name(const uchar** buffer)
{
	uchar name[256];
	const uchar* buf = *buffer;
	int j = 0;
	int i = 0;
	while(buf[i] != 0)
	{
		//if(i >= buflen || i > sizeof(name))
		//	return NULL;
		
		if(i != 0)
		{
			name[j] = '.';
			j += 1;
		}

		int len = buf[i];
		i += 1;

		memcpy(name+j, buf+i, len);
		i += len;
		j += len;
	}

	name[j] = '\0';

	*buffer += i + 1; //also jump over the last 0

	return strdup(name);
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uchar** buffer, const uchar* domain)
{
	uchar* buf = *buffer;
	const uchar* beg = domain;
	const uchar* pos;
	int len = 0;
	int i = 0;

	while(pos = strchr(beg, '.'))
	{
		len = pos - beg;
		buf[i] = len;
		i += 1;
		memcpy(buf+i, beg, len);
		i += len;

		beg = pos + 1;
	}

	len = strlen(domain) - (beg - domain);

	buf[i] = len;
	i += 1;

	memcpy(buf + i, beg, len);
	i += len;

	buf[i] = 0;
	i += 1;

	*buffer += i;
}


void decode_header(struct Message* msg, const uchar** buffer)
{
	msg->id = get16bits(buffer);

	uint fields = get16bits(buffer);
	msg->qr = (fields & QR_MASK) >> 15;
	msg->opcode = (fields & OPCODE_MASK) >> 11;
	msg->aa = (fields & AA_MASK) >> 10;
	msg->tc = (fields & TC_MASK) >> 9;
	msg->rd = (fields & RD_MASK) >> 8;
	msg->ra = (fields & RA_MASK) >> 7;
	msg->rcode = (fields & RCODE_MASK) >> 0;

	msg->qdCount = get16bits(buffer);
	msg->anCount = get16bits(buffer);
	msg->nsCount = get16bits(buffer);
	msg->arCount = get16bits(buffer);
}

void encode_header(struct Message* msg, uchar** buffer)
{
	put16bits(buffer, msg->id);

	int fields = 0;
	fields |= (msg->qr << 15) & QR_MASK;
	fields |= (msg->rcode << 0) & RCODE_MASK;
	// TODO: insert the rest of the fields
	put16bits(buffer, fields);

	put16bits(buffer, msg->qdCount);
	put16bits(buffer, msg->anCount);
	put16bits(buffer, msg->nsCount);
	put16bits(buffer, msg->arCount);
}

int decode_msg(struct Message* msg, const uchar* buffer, int size)
{
	char name[300];
	int i;

	decode_header(msg, &buffer);

	if((msg->anCount + msg->nsCount) != 0)
	{
		printf("Only questions expected!\n");
		return -1;
	}

	// parse questions
	uint qcount = msg->qdCount;
	struct Question* qs = msg->questions;
	for(i = 0; i < qcount; ++i)
	{
		struct Question* q = malloc(sizeof(struct Question));

		q->qName = decode_domain_name(&buffer);
		q->qType = get16bits(&buffer);
		q->qClass = get16bits(&buffer);

		//prepend question to questions list
		q->next = qs; 
		msg->questions = q;
	}

	// We do not expect any resource records to parse here.

	return 0;
}

// For every question in the message add a appropiate resource record
// in either section 'answers', 'authorities' or 'additionals'.
void resolver_process(struct Message* msg)
{
	struct ResourceRecord* beg;
	struct ResourceRecord* rr;
	struct Question* q;
	int rc;

	// leave most values intact for response
	msg->qr = 1; // this is a response
	msg->aa = 1; // this server is authoritative
	msg->ra = 0; // no recursion available
	msg->rcode = Ok_ResponseType;

	//should already be 0
	msg->anCount = 0;
	msg->nsCount = 0;
	msg->arCount = 0;

	//for every question append resource records
	q = msg->questions;
	while(q)
	{
		rr = malloc(sizeof(struct ResourceRecord));

		rr->name = strdup(q->qName);
		rr->type = q->qType;
		rr->class = q->qClass;
		rr->ttl = 60*60; //in seconds; 0 means no caching
		
		printf("Query for '%s'\n", q->qName);
		
		// We only can only answer two question types so far
		// and the answer (resource records) will be all put
		// into the answers list.
		// This behavior is probably non-standard!
		switch(q->qType)
		{
			case A_Resource_RecordType:
				rr->rd_length = 4;
				rc = get_A_Record(rr->rd_data.a_record.addr, q->qName);
				if(rc < 0)
					goto next;
				break;
			case AAAA_Resource_RecordType:
				rr->rd_length = 16;
				rc = get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qName);
				if(rc < 0)
					goto next;
				break;
			/*
			case NS_Resource_RecordType:
			case CNAME_Resource_RecordType:
			case SOA_Resource_RecordType:
			case PTR_Resource_RecordType:
			case MX_Resource_RecordType:
			case TXT_Resource_RecordType:
			*/
			default:
				msg->rcode = NotImplemented_ResponseType;
				printf("Cannot answer question of type %d.\n", q->qType);
				goto next;
		}

		msg->anCount++;

		// prepend resource record to answers list
		beg = msg->answers;
		msg->answers = rr;
		rr->next = beg;

		//jump here to omit question
		next:
		
		// process next question
		q = q->next;
	}
}

int encode_resource_records(struct ResourceRecord* rr, uchar** buffer) 
{
	int i;
	while(rr)
	{
		// Answer questions by attaching resource sections.
		encode_domain_name(buffer, rr->name);
		put16bits(buffer, rr->type);
		put16bits(buffer, rr->class);
		put32bits(buffer, rr->ttl);
		put16bits(buffer, rr->rd_length);
		
		switch(rr->type)
		{
			case A_Resource_RecordType:
				for(i = 0; i < 4; ++i)
					put8bits(buffer, rr->rd_data.a_record.addr[i]);
				break;
			case AAAA_Resource_RecordType:
				for(i = 0; i < 16; ++i)
					put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
				break;
			default:
				fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
			return 1;
		}
		
		rr = rr->next;
	}
	return 0;
}

int encode_msg(struct Message* msg, uchar** buffer)
{
	struct Question* q;
	int rc;

	encode_header(msg, buffer);

	q = msg->questions;
	while(q)
	{
		encode_domain_name(buffer, q->qName);
		put16bits(buffer, q->qType);
		put16bits(buffer, q->qClass);

		q = q->next;
	}

	rc = 0;
	rc |= encode_resource_records(msg->answers, buffer);
	rc |= encode_resource_records(msg->authorities, buffer);
	rc |= encode_resource_records(msg->additionals, buffer);

	return rc;
}

void free_resource_records(struct ResourceRecord* rr)
{
	struct ResourceRecord* next;

	while(rr) {
		free(rr->name);
		next = rr->next;
		free(rr);
		rr = next;
	}
}

void free_questions(struct Question* qq)
{
	struct Question* next;

	while(qq) {
		free(qq->qName);
		next = qq->next;
		free(qq);
		qq = next;
	}
}

int main()
{
	// buffer for input/output binary packet
	uchar buffer[BUF_SIZE];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	int nbytes, rc, buflen;
	int sock;
	int port = 9000;

	struct Message msg;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	rc = bind(sock, (struct sockaddr*) &addr, addr_len);

	if(rc != 0)
	{
		printf("Could not bind: %s\n", strerror(errno));
		return 1;
	}

	printf("Listening on port %u.\n", port);

	while(1)
	{
		memset(&msg, 0, sizeof(struct Message));

		free_questions(msg.questions);
		free_resource_records(msg.answers);
		free_resource_records(msg.authorities);
		free_resource_records(msg.additionals);

		nbytes = recvfrom(sock, buffer, sizeof(buffer), 0,
			(struct sockaddr *) &client_addr, &addr_len);

		if(decode_msg(&msg, buffer, nbytes) != 0) {
			continue;
		}

		/* Print query */
		print_query(&msg);

		resolver_process(&msg);

		/* Print response */
		print_query(&msg);

		uchar *p = buffer;
		if(encode_msg(&msg, &p) != 0) {
			continue;
		}

		int buflen = p - buffer;
		sendto(sock, buffer, buflen, 0, (struct sockaddr*) &client_addr, addr_len);
	}
}
