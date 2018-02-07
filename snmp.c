#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "snmp.h"

#define UINT32_TENTH (0xffffffff/10)
#define UINT32_TENTHMOD (0xffffffff%10)

uint8_t encode_oid(const char * oid_str, oid_t * oid)
{
	bool first = true;
	char c = -1;
	enum {NUM, DOT, EITHER} state;
	int byteidx, stridx, tmplen, valid;
	uint8_t tmp[5];
	uint32_t current = 0;

	byteidx = 0;
	oid->len = 0;
	for (stridx = 0; c; ++stridx)
	{
		c = oid_str[stridx];
		if (c == '.' || c == 0) {
			valid = (state != NUM);
			state = EITHER;
			if (stridx) {
				tmplen = 0;
				do {
					tmp[tmplen++] = current & 0x7f;
					current >>= 7;
				} while (current);
				while (tmplen--)
				{
					if (byteidx)
					{
						if (byteidx < MAX_OID_LEN) {
							uint8_t bitset = tmplen ? 0x80 : 0x00;
							oid->bytes[byteidx++] = tmp[tmplen] | bitset;
						} else {
							return 0;
						}
					}
					else if (first)
					{
						oid->bytes[byteidx] = tmp[tmplen];
						first = false;
					}
					else
					{
						oid->bytes[byteidx] = oid->bytes[byteidx] * 40 + tmp[tmplen];
						++byteidx;
					}
				}
			}
			current = 0;
		} else if (c >= '0' && c <= '9') {
			valid = (state != DOT);
			state = EITHER;

			uint32_t digit = c - '0';
			if (current > UINT32_TENTH || (current == UINT32_TENTH && digit > UINT32_TENTHMOD))
				return 0; /* oid too large for our implementation */
			current = current * 10 + digit;
		} else {
			valid = 0;
		}

		if (!valid) {
			return 0;
		}
	}

	return oid->len = byteidx;
}
