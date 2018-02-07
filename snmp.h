#ifndef _SNMP_H
#define _SNMP_H

#include <stdint.h>
#include <string.h>

#define MAX_OID_LEN 128
#define SNMP_PORT 161

typedef struct {
	uint32_t len;		/* if len_set == 1, len tells you the size in bytes */
	uint8_t len_set;	/* boolean that tells you whether the len has been calculated */
	uint8_t type;		/* data type (eg 0x02 = integer, 0x04 = octet string, etc) */
	uint16_t arr_len;	/* length of arr */
	void * arr;		/* an array of some type */
} data_t;

/* oid.arr should be preset to point to an array of uint8_t of size [MAX_OID_LEN] */
uint8_t encode_oid(const char * oid_str, data_t * oid);

#endif
