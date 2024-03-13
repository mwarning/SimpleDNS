#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <string.h>
#include <malloc.h>
#include <errno.h>
#include <string.h>
#include <stdbool.h>
#include <stdint.h>

#define BUFFER_SIZE 1500
#define MIN(x, y) ((x) <= (y) ? (x) : (y))

/*
 * This software is licensed under the CC0.
 *
 * This is a _basic_ DNS Server for educational use.
 * It does not prevent invalid packets from crashing
 * the server.
 *
 * To test start the program and issue a DNS request:
 *  dig @127.0.0.1 -p 9000 foo.bar.com
 */

/*
 * Masks and constants.
 */

static const uint32_t QR_MASK = 0x8000;
static const uint32_t OPCODE_MASK = 0x7800;
static const uint32_t AA_MASK = 0x0400;
static const uint32_t TC_MASK = 0x0200;
static const uint32_t RD_MASK = 0x0100;
static const uint32_t RA_MASK = 0x0080;
static const uint32_t RCODE_MASK = 0x000F;

/* Response Type */
enum
{
  Ok_ResponseType = 0,
  FormatError_ResponseType = 1,
  ServerFailure_ResponseType = 2,
  NameError_ResponseType = 3,
  NotImplemented_ResponseType = 4,
  Refused_ResponseType = 5
};

/* Resource Record Types */
enum
{
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
enum
{
  QUERY_OperationCode = 0,  /* standard query */
  IQUERY_OperationCode = 1, /* inverse query */
  STATUS_OperationCode = 2, /* server status request */
  NOTIFY_OperationCode = 4, /* request zone transfer */
  UPDATE_OperationCode = 5  /* change resource records */
};

/* Response Code */
enum
{
  NoError_ResponseCode = 0,
  FormatError_ResponseCode = 1,
  ServerFailure_ResponseCode = 2,
  NameError_ResponseCode = 3
};

/* Query Type */
enum
{
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
struct Question
{
  char *qName;
  uint16_t qType;
  uint16_t qClass;
  struct Question *next; // for linked list
};

/* Data part of a Resource Record */
union ResourceData
{
  struct
  {
    uint8_t txt_data_len;
    char *txt_data;
  } txt_record;
  struct
  {
    uint8_t addr[4];
  } a_record;
  struct
  {
    uint8_t addr[16];
  } aaaa_record;
};

/* Resource Record Section */
struct ResourceRecord
{
  char *name;
  uint16_t type;
  uint16_t class;
  uint32_t ttl;
  uint16_t rd_length;
  union ResourceData rd_data;
  struct ResourceRecord *next; // for linked list
};

struct Message
{
  uint16_t id; /* Identifier */

  /* Flags */
  uint16_t qr;     /* Query/Response Flag */
  uint16_t opcode; /* Operation Code */
  uint16_t aa;     /* Authoritative Answer Flag */
  uint16_t tc;     /* Truncation Flag */
  uint16_t rd;     /* Recursion Desired */
  uint16_t ra;     /* Recursion Available */
  uint16_t rcode;  /* Response Code */

  uint16_t qdCount; /* Question Count */
  uint16_t anCount; /* Answer Record Count */
  uint16_t nsCount; /* Authority Record Count */
  uint16_t arCount; /* Additional Record Count */

  /* At least one question; questions are copied to the response 1:1 */
  struct Question *questions;

  /*
   * Resource records to be send back.
   * Every resource record can be in any of the following places.
   * But every place has a different semantic.
   */
  struct ResourceRecord *answers;
  struct ResourceRecord *authorities;
  struct ResourceRecord *additionals;
};

bool get_A_Record(uint8_t addr[4], const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0)
  {
    addr[0] = 192;
    addr[1] = 168;
    addr[2] = 1;
    addr[3] = 1;
    return true;
  }
  else
  {
    return false;
  }
}

bool get_AAAA_Record(uint8_t addr[16], const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0)
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
    addr[15] = 0x01;
    return true;
  }
  else
  {
    return false;
  }
}

int get_TXT_Record(char **addr, const char domain_name[])
{
  if (strcmp("foo.bar.com", domain_name) == 0)
  {
    *addr = "abcdefg";
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

void print_hex(uint8_t *buf, size_t len)
{
  int i;
  printf("%zu bytes:\n", len);
  for (i = 0; i < len; i += 1)
    printf("%02x ", buf[i]);
  printf("\n");
}

void print_resource_record(struct ResourceRecord *rr)
{
  int i;
  while (rr)
  {
    printf("  ResourceRecord { name '%s', type %u, class %u, ttl %u, rd_length %u, ",
           rr->name,
           rr->type,
           rr->class,
           rr->ttl,
           rr->rd_length);

    union ResourceData *rd = &rr->rd_data;
    switch (rr->type)
    {
    case A_Resource_RecordType:
      printf("Address Resource Record { address ");

      for (i = 0; i < 4; i += 1)
        printf("%s%u", (i ? "." : ""), rd->a_record.addr[i]);

      printf(" }");
      break;
    case AAAA_Resource_RecordType:
      printf("AAAA Resource Record { address ");

      for (i = 0; i < 16; i += 1)
        printf("%s%02x", (i ? ":" : ""), rd->aaaa_record.addr[i]);

      printf(" }");
      break;
    case TXT_Resource_RecordType:
      printf("Text Resource Record { txt_data '%s' }",
             rd->txt_record.txt_data);
      break;
    default:
      printf("Unknown Resource Record { ??? }");
    }
    printf("}\n");
    rr = rr->next;
  }
}

void print_message(struct Message *msg)
{
  struct Question *q;

  printf("QUERY { ID: %02x", msg->id);
  printf(". FIELDS: [ QR: %u, OpCode: %u ]", msg->qr, msg->opcode);
  printf(", QDcount: %u", msg->qdCount);
  printf(", ANcount: %u", msg->anCount);
  printf(", NScount: %u", msg->nsCount);
  printf(", ARcount: %u,\n", msg->arCount);

  q = msg->questions;
  while (q)
  {
    printf("  Question { qName '%s', qType %u, qClass %u }\n",
           q->qName,
           q->qType,
           q->qClass);
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

size_t get16bits(const uint8_t **buffer, size_t *len)
{
  uint16_t value;

  if (*len < 2)
    return 0;

  memcpy(&value, *buffer, 2);
  *buffer += 2;
  *len -= 2;

  return ntohs(value);
}

void put8bits(uint8_t **buffer, uint8_t value)
{
  memcpy(*buffer, &value, 1);
  *buffer += 1;
}

void put16bits(uint8_t **buffer, uint16_t value)
{
  value = htons(value);
  memcpy(*buffer, &value, 2);
  *buffer += 2;
}

void put32bits(uint8_t **buffer, uint32_t value)
{
  value = htonl(value);
  memcpy(*buffer, &value, 4);
  *buffer += 4;
}

/*
 * Decoding/Encoding functions.
 */

// 3foo3bar3com0 => foo.bar.com (No full validation is done!)
char *decode_domain_name(const uint8_t **buf, size_t *len)
{
  if (*len == 0)
    return NULL;

  char domain[256];
  for (int i = 1; i < MIN(256, *len); i += 1)
  {
    uint8_t c = (*buf)[i];
    if (c == 0)
    {
      domain[i - 1] = 0;
      *buf += i + 1;
      *len -= i + 1;
      return strdup(domain);
    }
    else if ((c >= 'a' && c <= 'z') || c == '-')
    {
      domain[i - 1] = c;
    }
    else
    {
      domain[i - 1] = '.';
    }
  }

  return NULL;
}

// foo.bar.com => 3foo3bar3com0
void encode_domain_name(uint8_t **buffer, const char *domain)
{
  uint8_t *buf = *buffer;
  const char *beg = domain;
  const char *pos;
  int len = 0;
  int i = 0;

  while ((pos = strchr(beg, '.')))
  {
    len = pos - beg;
    buf[i] = len;
    i += 1;
    memcpy(buf + i, beg, len);
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

bool decode_header(struct Message *msg, const uint8_t **buffer, size_t *size)
{
  if (*size < 12)
    return false;

  msg->id = get16bits(buffer, size);

  uint32_t fields = get16bits(buffer, size);
  msg->qr = (fields & QR_MASK) >> 15;
  msg->opcode = (fields & OPCODE_MASK) >> 11;
  msg->aa = (fields & AA_MASK) >> 10;
  msg->tc = (fields & TC_MASK) >> 9;
  msg->rd = (fields & RD_MASK) >> 8;
  msg->ra = (fields & RA_MASK) >> 7;
  msg->rcode = (fields & RCODE_MASK) >> 0;

  msg->qdCount = get16bits(buffer, size);
  msg->anCount = get16bits(buffer, size);
  msg->nsCount = get16bits(buffer, size);
  msg->arCount = get16bits(buffer, size);

  return true;
}

void encode_header(struct Message *msg, uint8_t **buffer)
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

bool decode_msg(struct Message *msg, const uint8_t *buffer, size_t size)
{
  int i;

  if (decode_header(msg, &buffer, &size) == false)
    return false;

  if (msg->anCount != 0 || msg->nsCount != 0)
  {
    printf("Only questions expected!\n");
    return false;
  }

  // parse questions
  uint32_t qcount = msg->qdCount;
  for (i = 0; i < qcount; i += 1)
  {
    struct Question *q = malloc(sizeof(struct Question));
    if (q == NULL)
      return false;

    // prepend question to questions list
    q->next = msg->questions;
    q->qName = NULL;
    msg->questions = q;

    q->qName = decode_domain_name(&buffer, &size);
    if (q->qName == NULL)
    {
      printf("Failed to decode domain name!\n");
      return false;
    }

    q->qType = get16bits(&buffer, &size);
    q->qClass = get16bits(&buffer, &size);
  }

  // We do not expect any resource records to parse here.

  return true;
}

// For every question in the message add a appropiate resource record
// in either section 'answers', 'authorities' or 'additionals'.
void resolve_query(struct Message *msg)
{
  struct ResourceRecord *beg;
  struct ResourceRecord *rr;
  struct Question *q;

  // leave most values intact for response
  msg->qr = 1; // this is a response
  msg->aa = 1; // this server is authoritative
  msg->ra = 0; // no recursion available
  msg->rcode = Ok_ResponseType;

  // should already be 0
  msg->anCount = 0;
  msg->nsCount = 0;
  msg->arCount = 0;

  // for every question append resource records
  q = msg->questions;
  while (q)
  {
    rr = malloc(sizeof(struct ResourceRecord));
    memset(rr, 0, sizeof(struct ResourceRecord));

    rr->name = strdup(q->qName);
    rr->type = q->qType;
    rr->class = q->qClass;
    rr->ttl = 60 * 60; // in seconds; 0 means no caching

    printf("Query for '%s'\n", q->qName);

    // We only can only answer two question types so far
    // and the answer (resource records) will be all put
    // into the answers list.
    // This behavior is probably non-standard!
    switch (q->qType)
    {
    case A_Resource_RecordType:
      rr->rd_length = 4;
      if (!get_A_Record(rr->rd_data.a_record.addr, q->qName))
      {
        free(rr->name);
        free(rr);
        goto next;
      }
      break;
    case AAAA_Resource_RecordType:
      rr->rd_length = 16;
      if (!get_AAAA_Record(rr->rd_data.aaaa_record.addr, q->qName))
      {
        free(rr->name);
        free(rr);
        goto next;
      }
      break;
    case TXT_Resource_RecordType:
      if (!get_TXT_Record(&(rr->rd_data.txt_record.txt_data), q->qName))
      {
        free(rr->name);
        free(rr);
        goto next;
      }
      int txt_data_len = strlen(rr->rd_data.txt_record.txt_data);
      rr->rd_length = txt_data_len + 1;
      rr->rd_data.txt_record.txt_data_len = txt_data_len;
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
      free(rr);
      msg->rcode = NotImplemented_ResponseType;
      printf("Cannot answer question of type %d.\n", q->qType);
      goto next;
    }

    msg->anCount++;

    // prepend resource record to answers list
    beg = msg->answers;
    msg->answers = rr;
    rr->next = beg;

  // jump here to omit question
  next:

    // process next question
    q = q->next;
  }
}

/* @return false upon failure, true upon success */
bool encode_resource_records(struct ResourceRecord *rr, uint8_t **buffer)
{
  int i;

  while (rr)
  {
    // Answer questions by attaching resource sections.
    encode_domain_name(buffer, rr->name);
    put16bits(buffer, rr->type);
    put16bits(buffer, rr->class);
    put32bits(buffer, rr->ttl);
    put16bits(buffer, rr->rd_length);

    switch (rr->type)
    {
    case A_Resource_RecordType:
      for (i = 0; i < 4; i += 1)
        put8bits(buffer, rr->rd_data.a_record.addr[i]);
      break;
    case AAAA_Resource_RecordType:
      for (i = 0; i < 16; i += 1)
        put8bits(buffer, rr->rd_data.aaaa_record.addr[i]);
      break;
    case TXT_Resource_RecordType:
      put8bits(buffer, rr->rd_data.txt_record.txt_data_len);
      for (i = 0; i < rr->rd_data.txt_record.txt_data_len; i++)
        put8bits(buffer, rr->rd_data.txt_record.txt_data[i]);
      break;
    default:
      fprintf(stderr, "Unknown type %u. => Ignore resource record.\n", rr->type);
      return false;
    }

    rr = rr->next;
  }

  return true;
}

/* @return false upon failure, true upon success */
bool encode_msg(struct Message *msg, uint8_t **buffer)
{
  encode_header(msg, buffer);

  struct Question *q = msg->questions;
  while (q)
  {
    encode_domain_name(buffer, q->qName);
    put16bits(buffer, q->qType);
    put16bits(buffer, q->qClass);

    q = q->next;
  }

  if (!encode_resource_records(msg->answers, buffer))
  {
    return false;
  }

  if (!encode_resource_records(msg->authorities, buffer))
  {
    return false;
  }

  if (!encode_resource_records(msg->additionals, buffer))
  {
    return false;
  }

  return true;
}

void free_resource_records(struct ResourceRecord *rr)
{
  struct ResourceRecord *next;

  while (rr)
  {
    free(rr->name);
    next = rr->next;
    free(rr);
    rr = next;
  }
}

void free_questions(struct Question *qq)
{
  struct Question *next;

  while (qq)
  {
    free(qq->qName);
    next = qq->next;
    free(qq);
    qq = next;
  }
}

#ifdef FUZZER
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
  struct Message msg;
  memset(&msg, 0, sizeof(struct Message));

  // Assume `data` is a DNS query packet and `size` is its length.
  // You might need to adapt this if your decode_msg function expects
  // a different format or additional parameters.
  decode_msg(&msg, data, size);

  // Free any resources allocated by decode_msg to prevent memory leaks.
  free_questions(msg.questions);
  free_resource_records(msg.answers);
  free_resource_records(msg.authorities);
  free_resource_records(msg.additionals);

  return 0; // Non-zero return values are reserved for future use.
}
#else
int main(int argc, char *argv[])
{
  // buffer for input/output binary packet
  uint8_t buffer[BUFFER_SIZE];
  struct sockaddr_in client_addr;
  socklen_t addr_len = sizeof(struct sockaddr_in);
  struct sockaddr_in addr;
  int rc;
  ssize_t nbytes;
  int sock;
  int port = 9000; // Default port number

  // Check if a port number is passed as an argument
  if (argc > 1)
  {
    port = atoi(argv[1]); // Convert argument to integer and use it as the port number
    if (port <= 0 || port > 65535)
    {
      printf("Invalid port number. Please provide a port number between 1 and 65535.\n");
      return 1;
    }
  }

  struct Message msg;
  memset(&msg, 0, sizeof(struct Message));

  addr.sin_family = AF_INET;
  addr.sin_addr.s_addr = INADDR_ANY;
  addr.sin_port = htons(port);

  sock = socket(AF_INET, SOCK_DGRAM, 0);

  rc = bind(sock, (struct sockaddr *)&addr, addr_len);

  if (rc != 0)
  {
    printf("Could not bind: %s\n", strerror(errno));
    return 1;
  }

  printf("Listening on port %u.\n", port);

  while (1)
  {
    free_questions(msg.questions);
    free_resource_records(msg.answers);
    free_resource_records(msg.authorities);
    free_resource_records(msg.additionals);
    memset(&msg, 0, sizeof(struct Message));

    /* Receive DNS query */
    nbytes = recvfrom(sock, buffer, sizeof(buffer), 0, (struct sockaddr *)&client_addr, &addr_len);

    /* failed to read query */
    if (nbytes < 0)
    {
      continue;
    }

    /* Try to decode query */
    if (!decode_msg(&msg, buffer, nbytes))
    {
      continue;
    }

    /* Print query */
    print_message(&msg);

    /* Resolve query and put the answers into the query message */
    resolve_query(&msg);

    /* Print response */
    print_message(&msg);

    uint8_t *p = buffer;
    if (!encode_msg(&msg, &p))
    {
      continue;
    }

    /* Send DNS response */
    size_t buflen = p - buffer;
    sendto(sock, buffer, buflen, 0, (struct sockaddr *)&client_addr, addr_len);
  }
}
#endif