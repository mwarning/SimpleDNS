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

// Response Type
enum {
	Ok_ResponseType = 0,
	FormatError_ResponseType = 1,
	ServerFailure_ResponseType = 2,
	NameError_ResponseType = 3,
	NotImplemented_ResponseType = 4,
	Refused_ResponseType = 5
};

// Resource Record Types
enum {
	A_Resource_RecordType = 1,
	NS_Resource_RecordType = 2,
	CNAME_Resource_RecordType = 5,
	SOA_Resource_RecordType = 6,
	PTR_Resource_RecordType = 12,
	MX_Resource_RecordType = 15,
	TXT_Resource_RecordType = 16,
	AAAA_Resource_RecordType = 28
};

// Operation Code
enum {
	QUERY_OperationCode = 0, // standard query
	IQUERY_OperationCode = 1, // inverse query
	STATUS_OperationCode = 2, // server status request
	NOTIFY_OperationCode = 4, // request zone transfer
	UPDATE_OperationCode = 5, // change resource records
};

// Response Code
enum {
	NoError_ResponseCode = 0,
	FormatError_ResponseCode = 1,
	ServerFailure_ResponseCode = 2,
	NameError_ResponseCode = 3
};

// Query Type
enum {
	IXFR_QueryType = 251,
	AXFR_QueryType = 252,
	MAILB_QueryType = 253,
	MAILA_QueryType = 254,
	STAR_QueryType = 255
};

/*
* Custom allocator.
*/

// We use a global block allocator
// for ever heap allocation to simplify
// memory handling.
char* gbuffer = 0;
size_t gbuffer_max_size = 0;
size_t gbuffer_curr_size = 0;


void* gmalloc(size_t size)
{
	if(gbuffer_curr_size + size >= gbuffer_max_size)
		return NULL;
	
	size_t cur = gbuffer_curr_size;
	gbuffer_curr_size += size;
	return gbuffer + cur;
}

/*
* Types.
*/

// QuestionSection
struct Question
{
	uchar* qName;
	uint qType;
	uint qClass;
	struct Question* next; // for linked list
};

union ResourceData
{
	struct { char* txt_data; } txt_record;
	struct { uchar addr[4]; } a_record;
	struct { char* name; } name_server_record;
	struct { char* name; } cname_record;
	struct { char* name; } ptr_record;
	struct { uint preference; char* exchange; } mx_record;
	struct { char* MName; char* RName;
		uint serial; uint refresh; uint retry;
		uint expire; uint minimum; } soa_record;
	struct { uchar addr[16]; } aaaa_record;
};

// DNS Message Resource Record Field Formats 
struct ResourceRecord
{
	char* name;
	uint type;
	uint class;
	uint ttl;
	uint rd_length;
	union ResourceData rd_data;

	struct ResourceRecord* next; // for linked list
};

struct Message
{
	uint id; // Identifier

	//flags
	uint qr; // Query/Response Flag (0 = query, 1 = response)
	uint opcode; // Operation Code
	uint aa; // Authoritative Answer Flag (0 = non-authoritative, 1 = authoritative)
	uint tc; // Truncation Flag
	uint rd; // Recursion Desired
	uint ra; // Recursion Available
	uint rcode; // Response Code

	uint qdCount; // Question Count
	uint anCount; // Answer Record Count:
	uint nsCount; // Authority Record Count
	uint arCount; // Additional Record Count

	// at least one question; questions are copied to response 1:1
	struct Question* questions;

	// resource records to be send back
	// Every resource record can be in any of the following places.
	// But every place has a different semantic.
	struct ResourceRecord* answers;
	struct ResourceRecord* authorities;
	struct ResourceRecord* additionals;
};


int get_A_Record(uchar addr[4], char* domain_name)
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

int get_AAAA_Record(uchar addr[16], char* domain_name)
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

int get16bits(const uchar** buffer)
{
	int value = (*buffer)[0];
	value = value << 8;
	value += (*buffer)[1];
	(*buffer) += 2;
	return value;
}

void put8bits(uchar** buffer, uchar value)
{
	(*buffer)[0] = value;
	(*buffer) += 1;
}

void put16bits(uchar** buffer, uint value)
{
	(*buffer)[0] = (value & 0xFF00) >> 8;
	(*buffer)[1] = value & 0xFF;
	(*buffer) += 2;
}

void put32bits(uchar** buffer, ulong value)
{
	(*buffer)[0] = (value & 0xFF000000) >> 24;
	(*buffer)[1] = (value & 0xFF0000) >> 16;
	(*buffer)[2] = (value & 0xFF00) >> 16;
	(*buffer)[3] = (value & 0xFF) >> 16;
	(*buffer) += 4;
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

	char* dup = (char*) gmalloc(j+1);
	if(dup)
	{
		memcpy(dup, name, j+1);
		return dup;
	}
	else
	{
		return NULL;
	}
}

// foo.bar.com => 3foo3bar3com0
void code_domain_name(uchar** buffer, const uchar* domain)
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

void code_header(struct Message* msg, uchar** buffer)
{
	put16bits(buffer, msg->id);

	int fields = 0;
	fields |= (msg->qr << 15) & QR_MASK;
	fields |= (msg->rcode << 0) & RCODE_MASK;
	// TODO: insert the rest of the field
	put16bits(buffer, fields);

	put16bits(buffer, msg->qdCount);
	put16bits(buffer, msg->anCount);
	put16bits(buffer, msg->nsCount);
	put16bits(buffer, msg->arCount);
}

int decode_query(struct Message* msg, const uchar* buffer, int size)
{
	int i;

	decode_header(msg, &buffer);

	if((msg->anCount+msg->nsCount+msg->arCount) != 0)
	{
		printf("Only questions expected!\n");
		return -1;
	}
	
	// parse questions
	uint qcount = msg->qdCount;
	struct Question* qs = msg->questions;
	for(i = 0; i < qcount; ++i)
	{
		struct Question* q = gmalloc(sizeof(struct Question));
		if(q == NULL)
			return -1;
		
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
	struct Question* q = msg->questions;
	while(q)
	{
		struct ResourceRecord* rr = gmalloc(sizeof(struct ResourceRecord));

		rr->name = q->qName;
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
		struct ResourceRecord* a = msg->answers;
		msg->answers = rr;
		rr->next = a;

		//jump here to omit question
		next:
		
		// process next question
		q = q->next;
	}
}


int code_resource_records(struct ResourceRecord* rr, uchar** buffer) 
{
	int i;
	while(rr)
	{
		// Answer questions by attaching resource sections.
		code_domain_name(buffer, rr->name);
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
		}
		
		rr = rr->next;
	}
}

int code_response(struct Message* msg, uchar* buffer) 
{
	const uchar* buf = buffer;

	code_header(msg, &buffer);

	struct Question* q = msg->questions;
	while(q)
	{
		code_domain_name(&buffer, q->qName);
		put16bits(&buffer, q->qType);
		put16bits(&buffer, q->qClass);

		q = q->next;
	}
	
	code_resource_records(msg->answers, &buffer);
	code_resource_records(msg->authorities, &buffer);
	code_resource_records(msg->additionals, &buffer);

	return buffer - buf;
}

// Initialize a global buffer to simplify memory handling.
// No complex freeing needed. :-)
void init_gbuffer(size_t size)
{
	gbuffer = malloc(size);
	gbuffer_max_size = size;
	gbuffer_curr_size = 0;
}

int main()
{
	// buffer for input/output binary packet
	char buffer[BUF_SIZE];
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(struct sockaddr_in);
	struct sockaddr_in addr;
	int sock;
	int port = 9000;

	// buffer for response/request structures
	gbuffer = malloc(2 * BUF_SIZE);
	gbuffer_max_size = (2 * BUF_SIZE);
	gbuffer_curr_size = 0;

	struct Message msg;

	addr.sin_family = AF_INET;
	addr.sin_addr.s_addr = INADDR_ANY;
	addr.sin_port = htons(port);

	sock = socket(AF_INET, SOCK_DGRAM, 0);

	int rc = bind(sock, (struct sockaddr*) &addr, addr_len);

	if(rc != 0)
	{
		printf("Could not bind: %s\n", strerror(errno));
		return 1;
	}

	printf("Listening on port %u.\n", port);

	while(1)
	{
		gbuffer_curr_size = 0;

		memset(&msg, 0, sizeof(struct Message));

		int nbytes = recvfrom(sock, buffer, sizeof(buffer), 0,
			(struct sockaddr *) &client_addr, &addr_len);

		nbytes = decode_query(&msg, buffer, nbytes);
		if(nbytes < 0)
			continue;
	
		// print query
		print_query(&msg);

		resolver_process(&msg);

		// print response
		print_query(&msg);

		nbytes = code_response(&msg, buffer);
		if(nbytes < 0)
			continue;

		sendto(sock, buffer, nbytes, 0, (struct sockaddr*) &client_addr, addr_len);
	}
}
