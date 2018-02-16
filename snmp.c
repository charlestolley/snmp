#include <arpa/inet.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>

#include "snmp.h"

#define UINT32_TENTH (0xffffffff/10)
#define UINT32_TENTHMOD (0xffffffff%10)

int calculate_len(data_t * data)
{
	if (data->flags & LEN_SET)
		return data->len;

	uint16_t i;
	uint32_t len, len_len;

	data->len = 0;
	data_t * arr = (data_t *) data->arr;

	for (i = 0; i < data->arr_len; ++i)
	{
		calculate_len(&arr[i]);
		len = arr[i].len;
		if (len > MAX_DATA_LEN) {
			return -1;
		} else if (len > 0x7f) {
			len_len = 3;
		} else {
			len_len = 1;
		}
		data->len += arr[i].len + len_len + 1;
	}
	data->flags |= LEN_SET;
	return data->len;
}

void encode_int(data_t * data, uint32_t number)
{
	uint8_t tmp[4];
	uint8_t tmplen = 0;
	do {
		tmp[tmplen++] = number;
		number >>= 8;
	} while (number);

	data->len = tmplen;
	data->flags = LEN_SET | PRINTABLE;
	data->type = TYPE_INT;
	data->arr_len = tmplen;

	if (data->arr == NULL)
		data->arr = malloc(tmplen);

	uint8_t * ptr = data->arr;
	while (tmplen--)
	{
		*(ptr++) = tmp[tmplen];
	}
}

void encode_null(data_t * data)
{
	data->len = 0;
	data->flags = LEN_SET | PRINTABLE;
	data->type = TYPE_NULL;
	data->arr_len = 0;
	data->arr = NULL;
}

uint8_t encode_oid(const char * oid_str, data_t * oid)
{
	bool first = true, valid;
	char c = -1;
	enum {NUM, DOT, EITHER} state = EITHER;
	int byteidx, stridx, tmplen;

	uint8_t static_bytes[MAX_OID_LEN];
	uint8_t * oid_bytes;
	if (oid->arr == NULL)
		oid_bytes = static_bytes;
	else
		oid_bytes = (uint8_t *) oid->arr;

	uint8_t tmp[5];
	uint32_t current = 0;

	oid->type = TYPE_OID;

	byteidx = 0;
	oid->arr_len = 0;
	oid->len = 0;
	oid->flags |= LEN_SET | PRINTABLE;
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
							oid_bytes[byteidx++] = tmp[tmplen] | bitset;
						} else {
							return 0;
						}
					}
					else if (first)
					{
						oid_bytes[byteidx] = tmp[tmplen];
						first = false;
					}
					else
					{
						oid_bytes[byteidx] = oid_bytes[byteidx] * 40 + tmp[tmplen];
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
			valid = false;
		}

		if (!valid) {
			return 0;
		}
	}

	if (oid_bytes == static_bytes)
	{
		oid->arr = malloc(byteidx);
		strncpy((uint8_t*) oid->arr, static_bytes, byteidx);
	}

	oid->arr_len = byteidx;
	return oid->len = byteidx;
}

int print_data(data_t * data, uint8_t * bytes, uint16_t max_bytes)
{
	uint32_t i, j;

	calculate_len(data);

	i = 0;
	bytes[i++] = data->type;
	if (data->len > MAX_DATA_LEN) {
		bytes[i++] = 0;
		return i;
	} else if (data->len > 0x7f) {
		bytes[i++] = (data->len >> 7) | 0x80;
		bytes[i++] = 1;
	}
	bytes[i++] = (uint8_t) data->len & 0x7f;

	if (data->len > max_bytes - i) {
		bytes[1] = 0;
		return 2;
	}

	if (data->flags & PRINTABLE) {
		uint8_t * arr = (uint8_t*) data->arr;
		for (j = 0; j < data->len; ++j) {
			bytes[i++] = arr[j];
		}
	} else {
		data_t * arr = (data_t*) data->arr;
		for (j = 0; j < data->arr_len; ++j) {
			i += print_data(&arr[j], &bytes[i], max_bytes - i);
		}
	}
	return i;
}
