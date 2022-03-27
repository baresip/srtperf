/**
 * @file hexdump.c Hexdump buffers
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <re.h>
#include "core.h"


void hexdump_dual(FILE *f,
		  const void *ep, size_t elen,
		  const void *ap, size_t alen)
{
	const uint8_t *ebuf = ep;
	const uint8_t *abuf = ap;
	size_t i, j, len;
#define WIDTH 8

	if (!f || !ep || !ap)
		return;

	len = max(elen, alen);

	(void)re_fprintf(f, "\nOffset:   Expected (%u bytes):    "
			 "   Actual (%u bytes):\n", elen, alen);

	for (i=0; i < len; i += WIDTH) {

		(void)re_fprintf(f, "0x%04x   ", i);

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < elen)
				(void)re_fprintf(f, " %02x", ebuf[pos]);
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "    ");

		for (j=0; j<WIDTH; j++) {
			const size_t pos = i+j;
			if (pos < alen) {
				bool wrong;

				if (pos < elen)
					wrong = ebuf[pos] != abuf[pos];
				else
					wrong = true;

				if (wrong)
					(void)re_fprintf(f, "\x1b[33m");
				(void)re_fprintf(f, " %02x", abuf[pos]);
				if (wrong)
					(void)re_fprintf(f, "\x1b[;m");
			}
			else
				(void)re_fprintf(f, "   ");
		}

		(void)re_fprintf(f, "\n");
	}

	(void)re_fprintf(f, "\n");
}
