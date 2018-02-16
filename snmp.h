#ifndef _SNMP_H
#define _SNMP_H

#include <stdint.h>
#include <string.h>

#define MAX_DATA_LEN ((0x7f << 7) | 0x7f)
#define MAX_OID_LEN 128
#define SNMP_PORT 161

#define LEN_SET 0x01	/* if this bit is zero, the value of len is not to be trusted */
#define PRINTABLE 0x02	/* if this bit is set, arr can be treated as a raw (uint8_t*) */
typedef struct {
	uint32_t len;		/* if (flags & LEN_SET != 0), len tells you the size in bytes */
	uint8_t flags;		/* contains some metadata */
	uint8_t type;		/* data type (eg 0x02 = integer, 0x04 = octet string, etc) */
	uint16_t arr_len;	/* length of arr */
	void * arr;		/* an array of some type */
} data_t;

/* recursively calculates the length of data; assumes that (flags | LEN_SET != 0) for all primitive data types */
int calculate_len(data_t * data);

/* if oid->arr is NULL, an array of length 4 will be malloc'd (must be free'd by caller) */
void encode_int(data_t * data, uint32_t number);

void encode_string(data_t * data, char * string, size_t len);

/* encodes a data type as null; no prerequisites */
void encode_null(data_t * data);

#define TYPE_INT 0x02
#define TYPE_OCTETSTR 0x04
#define TYPE_NULL 0x05
#define TYPE_OID 0x06
/*	oid->arr should be preset to point to an array of uint8_t of at least size MAX_OID_LEN
	if oid->arr is NULL, an array of size oid->len will be malloc'd (must be free'd by caller)*/
uint8_t encode_oid(data_t * oid, const char * oid_str);

/* this is a development-grade function that composes a get request and prints the contents */
void print_get_pdu(char * oid_str)

/*	serializes data into a byte array, assuming max_bytes is large enough
	return value is the length (in bytes) of the final encoded object */
int print_data(data_t * data, uint8_t * bytes, uint16_t max_bytes);

#endif
