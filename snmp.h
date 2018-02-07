#ifndef _SNMP_H
#define _SNMP_H

#include <stdint.h>
#include <string.h>

#define MAX_OID_LEN 128
#define SNMP_PORT 161

typedef struct {
	uint8_t len;
	uint8_t bytes[MAX_OID_LEN];
} oid_t;

uint8_t encode_oid(const char * oid_str, oid_t * oid);

#endif
