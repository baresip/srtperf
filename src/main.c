/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 Creytiv.com
 */

#ifdef HAVE_LIBSRTP
#if defined (__GNUC__) && !defined (asm)
#define asm __asm__  /* workaround */
#endif
#include <srtp/srtp.h>
#endif

#include <openssl/crypto.h>
#include <sys/time.h>
#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <math.h>
#include <re.h>


#define DEBUG_MODULE "srtperf"
#define DEBUG_LEVEL 6
#include <re_dbg.h>


#define SSRC 0x01020304
#define MAX_KEY_LEN 32
#define SALT_LEN 14


/* 128 - 256 bits key */
static const uint8_t master_key[MAX_KEY_LEN + SALT_LEN] = {
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,

	0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
};
static size_t master_key_len = 16;    /* bytes, excl. Salt */

static uint16_t seq_init = 1;
static bool add_csrc = false;


struct packets {
	struct mbuf **mbv;
	size_t num;
	size_t rtp_hdr_len;
	size_t payload_len;
	size_t rtp_packet_len;
	size_t srtp_packet_len;
};


static int packets_init(struct packets *mbv, unsigned num,
			const uint8_t *payload, unsigned payload_len,
			unsigned auth_bits)
{
	struct rtp_header hdr;
	unsigned i;
	uint16_t seq = seq_init;
	int err = 0;

	memset(&hdr, 0, sizeof(hdr));
	hdr.ver  = RTP_VERSION;
	hdr.ssrc = SSRC;

	if (add_csrc) {
		hdr.cc = 1;
		hdr.csrc[0] = 0x0000caca;
	}

	mbv->mbv = mem_zalloc(num * sizeof(struct mbuf *), NULL);
	if (!mbv->mbv)
		return ENOMEM;

	mbv->num = num;
	mbv->rtp_hdr_len = RTP_HEADER_SIZE + hdr.cc*4;
	mbv->payload_len = payload_len;
	mbv->rtp_packet_len = mbv->rtp_hdr_len + payload_len;
	mbv->srtp_packet_len = mbv->rtp_hdr_len + payload_len + auth_bits/8;

	for (i=0; i<num; i++) {

		size_t len = mbv->rtp_packet_len + 12;

		hdr.seq = seq++;

		mbv->mbv[i] = mbuf_alloc(len);
		if (!mbv->mbv[i])
			return ENOMEM;

		err = rtp_hdr_encode(mbv->mbv[i], &hdr);
		if (err)
			break;

		err = mbuf_write_mem(mbv->mbv[i], payload, payload_len);
		if (err)
			break;
	}

	return err;
}


static void mbv_reset(struct packets *mbv)
{
	unsigned i;
	for (i=0; i<mbv->num; i++) {
		mem_deref(mbv->mbv[i]);
	}
	mem_deref(mbv->mbv);
}


#ifdef HAVE_LIBSRTP
static int perftest_libsrtp_encode(struct packets *mbv, unsigned auth_bits)
{
	srtp_t srtp = 0;
	srtp_policy_t policy_tx;
	crypto_policy_t policy;
	unsigned i;
	err_status_t e;
	const int exp_len = (int)(mbv->srtp_packet_len);
	int len, err = 0;

	memset(&policy, 0, sizeof(policy));
	policy.cipher_type     = AES_128_ICM;
	policy.cipher_key_len  = (int)master_key_len + SALT_LEN;
	policy.auth_type       = HMAC_SHA1;
	policy.auth_key_len    = 20;
	policy.auth_tag_len    = auth_bits/8;
	policy.sec_serv        = sec_serv_conf | sec_serv_auth;

	memset(&policy_tx, 0, sizeof(policy_tx));
	policy_tx.rtp = policy;
	policy_tx.rtcp = policy;
	policy_tx.ssrc.type = ssrc_any_outbound;
	policy_tx.key = (uint8_t *)master_key;
	policy_tx.next = NULL;

	e = srtp_create(&srtp, &policy_tx);
	if (e != err_status_ok) {
		DEBUG_WARNING("srtp_create failed (e=%d)\n", e);
		err = EPROTO;
		goto out;
	}

	for (i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;
		mb->end = mbv->rtp_packet_len;

		len = (int)mbuf_get_left(mb);

		e = srtp_protect(srtp, mbuf_buf(mb), &len);
		if (err_status_ok != e) {
			DEBUG_WARNING("libsrtp: srtp_protect: e = %d\n", e);
			err = EPROTO;
			break;
		}
		if (len != exp_len) {
			DEBUG_WARNING("libsrtp: len: expect %d, got %d\n",
				      len, exp_len);
			err = EPROTO;
			break;
		}
		mb->end = len;
	}

 out:
#if 0
	if (srtp)
		srtp_dealloc(srtp);
#endif

	return err;
}


static int perftest_libsrtp_decode(struct packets *mbv, unsigned auth_bits)
{
	srtp_t srtp = 0;
	srtp_policy_t policy_rx;
	crypto_policy_t policy;
	unsigned i;
	err_status_t e;
	const int exp_len_rtp = (int)mbv->rtp_packet_len;
	int len, err = 0;

	memset(&policy, 0, sizeof(policy));
	policy.cipher_type     = AES_128_ICM;
	policy.cipher_key_len  = (int)master_key_len + SALT_LEN;
	policy.auth_type       = HMAC_SHA1;
	policy.auth_key_len    = 20;
	policy.auth_tag_len    = auth_bits/8;
	policy.sec_serv        = sec_serv_conf;
	policy.sec_serv       |= sec_serv_auth;

	memset(&policy_rx, 0, sizeof(policy_rx));
	policy_rx.rtp = policy;
	policy_rx.rtcp = policy;
	policy_rx.ssrc.type = ssrc_any_inbound;
	policy_rx.key = (uint8_t *)master_key;
	policy_rx.next = NULL;

	e = srtp_create(&srtp, &policy_rx);
	if (e != err_status_ok) {
		DEBUG_WARNING("srtp_create failed (e=%d)\n", e);
		err = EPROTO;
		goto out;
	}

	for (i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;

		len = (int)mbuf_get_left(mb);

		e = srtp_unprotect(srtp, mbuf_buf(mb), &len);
		if (err_status_ok != e) {
			DEBUG_WARNING("libsrtp: srtp_unprotect: e = %d\n", e);
			err = EPROTO;
			break;
		}
		if (len != exp_len_rtp) {
			DEBUG_WARNING("libsrtp: len: expect %d, got %d\n",
				      len, exp_len_rtp);
			err = EPROTO;
			break;
		}
		mb->end = len;
	}

 out:
#if 0
	if (srtp)
		srtp_dealloc(srtp);
#endif

	return err;
}
#endif


static int perftest_native_encode(struct packets *mbv, enum srtp_suite suite)
{
	struct srtp *ctx = NULL;
	unsigned i;
	int err;

	err = srtp_alloc(&ctx, suite, master_key, master_key_len + SALT_LEN,
			 0);
	if (err) {
		DEBUG_WARNING("srtp_alloc failed: %m\n", err);
		goto out;
	}

	for (i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;
		mb->end = mbv->rtp_packet_len;

		err = srtp_encrypt(ctx, mb);
		if (err)
			break;
		if (mb->end != mbv->srtp_packet_len) {
			DEBUG_WARNING("native: i=%u len\n", i);
			err = EPROTO;
			break;
		}
	}

 out:
	mem_deref(ctx);

	return err;
}


static int perftest_native_decode(struct packets *mbv, enum srtp_suite suite)
{
	struct srtp *ctx = NULL;
	unsigned i;
	int err;

	err = srtp_alloc(&ctx, suite, master_key, master_key_len + SALT_LEN,
			 0);
	if (err)
		goto out;

	for (i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;

		err = srtp_decrypt(ctx, mb);
		if (err) {
			DEBUG_WARNING("srtp_decrypt failed: i=%u\n", i);
			break;
		}
		if (mb->end != mbv->rtp_packet_len) {
			DEBUG_WARNING("native: i=%u len\n", i);
			err = EPROTO;
			break;
		}
	}

 out:
	mem_deref(ctx);

	return err;
}


static void test_hexdump_dual(FILE *f,
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


static uint64_t tmr_microseconds(void)
{
	struct timeval now;
	uint64_t usec;

	if (0 != gettimeofday(&now, NULL)) {
		DEBUG_WARNING("jiffies: gettimeofday() failed (%m)\n", errno);
		return 0;
	}

	usec  = (uint64_t)now.tv_sec * (uint64_t)1000000;
	usec += now.tv_usec;

	return usec;
}


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "srtperf -a <bits> -e <bits>"
			 " -n <NUM> -p <bytes> -h\n");
	(void)re_fprintf(stderr, "\t-a <bits>   Authentication bits\n");
	(void)re_fprintf(stderr, "\t-c          Add Contributing source\n");
	(void)re_fprintf(stderr, "\t-e <bits>   Encryption key bits\n");
	(void)re_fprintf(stderr, "\t-n NUM      Number of rounds in test\n");
	(void)re_fprintf(stderr, "\t-p <bytes>  RTP Payload size in bytes\n");
	(void)re_fprintf(stderr, "\t-s <Seq>    Initial sequence number\n");
	(void)re_fprintf(stderr, "\t-h          Show summary of options\n");
	(void)re_fprintf(stderr, "\t-v          Verbose output\n");
}


int main(int argc, char *argv[])
{
	unsigned auth_bits = 80, payload_len = 160, num = 100;
	uint64_t t0, t1, t2;
	struct packets mbv_libsrtp, mbv_native;
	uint8_t *payload = NULL;
	unsigned i;
	bool verbose = false;
	enum srtp_suite suite;
	int err = 0;

	for (;;) {

		const int c = getopt(argc, argv, "a:ce:p:n:s:hv");
		if (0 > c)
			break;

		switch (c) {

		case 'a':
			auth_bits = atoi(optarg);
			break;

		case 'c':
			add_csrc = true;
			break;

		case 'e':
			master_key_len = atoi(optarg)/8;
			break;

		case 'p':
			payload_len = atoi(optarg);
			break;

		case 'n':
			num = atoi(optarg);
			break;

		case 's':
			seq_init = atoi(optarg);
			break;

		case 'v':
			verbose = true;
			break;

		case '?':
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}

	libre_init();

	re_printf("srtperf -- SRTP performance testing program\n");
	re_printf("parameters:    seq = %u, payload = %u bytes,"
		  " encr_key = %u bits, auth_bits = %u\n",
		  seq_init, payload_len, master_key_len*8, auth_bits);
	re_printf("build:         %H\n", sys_build_get, 0);
	re_printf("compiler:      %s\n", __VERSION__);
	re_printf("libre:         %s\n", sys_libre_version_get());
	re_printf("os:            %s\n", sys_os_get());
	re_printf("arch:          %s\n", sys_arch_get());

#ifdef USE_OPENSSL
	re_printf("openssl aesni: %s\n",
		  (OPENSSL_ia32cap & (1ULL<<57))
		  ? "supported" : "not supported");
	re_printf("openssl info:  %s\n%s\n",
		  SSLeay_version(SSLEAY_VERSION),
		  SSLeay_version(SSLEAY_CFLAGS));
#endif

#ifdef HAVE_LIBSRTP
	re_printf("HAVE_LIBSRTP:  yes\n");
#else
	re_printf("HAVE_LIBSRTP:  no\n");
#endif

	re_printf("\n");

#ifdef HAVE_LIBSRTP
	{
		err_status_t e;
		if (verbose)
			re_printf("initializing libsrtp..\n");

		e = srtp_init();
		if (err_status_ok != e) {
			DEBUG_WARNING("srtp_init() failed (e=%d)\n", e);
			return ENOSYS;
		}

		if (verbose)
			re_printf("libsrtp initialized OK\n");
	}
#endif

	payload = mem_alloc(payload_len, NULL);

	rand_bytes(payload, payload_len);

	if (master_key_len == 16 && auth_bits == 32)
		suite = SRTP_AES_CM_128_HMAC_SHA1_32;
	else if (master_key_len == 16 && auth_bits == 80)
		suite = SRTP_AES_CM_128_HMAC_SHA1_80;
	else if (master_key_len == 32 && auth_bits == 32)
		suite = SRTP_AES_256_CM_HMAC_SHA1_32;
	else if (master_key_len == 32 && auth_bits == 80)
		suite = SRTP_AES_256_CM_HMAC_SHA1_80;
	else {
		re_fprintf(stderr, "no matching suite -- invalid parameters"
			   " (master_key = %u bytes, auth_bits = %u)\n",
			   master_key_len, auth_bits);
		err = EINVAL;
		goto out;
	}

	if (verbose)
		re_printf("creating %u packets\n", num);
	err |= packets_init(&mbv_libsrtp, num, payload, payload_len,
			    auth_bits);
	err |= packets_init(&mbv_native, num, payload, payload_len,
			    auth_bits);
	if (err)
		goto out;


	/*
	 * Start timing now
	 */
	if (verbose)
		re_printf("starting encryption tests..\n");

	t0 = tmr_microseconds();
#ifdef HAVE_LIBSRTP
	err = perftest_libsrtp_encode(&mbv_libsrtp, auth_bits);
	if (err) {
		re_fprintf(stderr, "perftest_libsrtp_encode failed: %m\n",
			   err);
		goto out;
	}
#endif
	t1 = tmr_microseconds();
	err = perftest_native_encode(&mbv_native, suite);
	t2 = tmr_microseconds();
	if (err) {
		re_fprintf(stderr, "perftest_native_encode failed: %m\n", err);
		goto out;
	}

	re_printf("libsrtp encrypt %u times:    %d usec\n", num, (int)(t1-t0));
	re_printf("native  encrypt %u times:    %d usec   (%.1f %%)\n",
		  num, (int)(t2-t1),
		  100.0 * ((int)(t2-t1) - (int)(t1-t0)) / (t1-t0) );

	re_printf("libsrtp packets per. second:   %lld\n",
		  1000000LL * num / (int)(t1-t0));
	re_printf("native packets per. second:    %lld\n",
		  1000000LL * num / (int)(t2-t1));


#ifdef HAVE_LIBSRTP
	/* compare all SRTP packets */
	for (i=0; i<num; i++) {

		if (mbv_libsrtp.mbv[i]->end !=
		    mbv_native.mbv[i]->end) {
			err = EBADMSG;
			DEBUG_WARNING("SRTP packet %u length mismatch"
				      " (libsrtp = %u, native = %u)\n", i,
				      mbv_libsrtp.mbv[i]->end,
				      mbv_native.mbv[i]->end);
			break;
		}
		if (0 != memcmp(mbv_libsrtp.mbv[i]->buf,
				mbv_native.mbv[i]->buf,
				mbv_libsrtp.mbv[i]->end)) {
			err = EBADMSG;
			DEBUG_WARNING("SRTP packet %u content mismatch\n", i);

			test_hexdump_dual(stderr,
					  mbv_libsrtp.mbv[i]->buf,
					  mbv_libsrtp.mbv[i]->end,
					  mbv_native.mbv[i]->buf,
					  mbv_native.mbv[i]->end);
			break;
		}

		if (verbose) {
			re_printf("SRTP packet OK\n");
		}
	}
	if (!err)
		re_printf("verified %u SRTP-packets ok\n", i);
#endif

	re_printf("\n");

	t0 = tmr_microseconds();
#ifdef HAVE_LIBSRTP
	err = perftest_libsrtp_decode(&mbv_libsrtp, auth_bits);
	if (err) {
		re_fprintf(stderr, "perftest_libsrtp_decode failed:"
			   " %m\n", err);
		goto out;
	}
#endif
	t1 = tmr_microseconds();
	err = perftest_native_decode(&mbv_native, suite);
	t2 = tmr_microseconds();
	if (err) {
		re_fprintf(stderr, "perftest_native_decode failed: %m\n", err);
		goto out;
	}

	re_printf("libsrtp decrypt %u times:    %d usec\n", num, (int)(t1-t0));
	re_printf("native  decrypt %u times:    %d usec   (%.1f %%)\n",
		  num, (int)(t2-t1),
		  100.0 * ((int)(t2-t1) - (int)(t1-t0)) / (t1-t0) );

	/* verify all decrypted RTP-packets */
	for (i=0; i<num; i++) {

		size_t hdr_len = mbv_native.rtp_hdr_len;
		size_t rtp_len = mbv_native.rtp_packet_len;

		if (mbv_native.mbv[i]->end != rtp_len) {
			err = EBADMSG;
			DEBUG_WARNING("RTP packet %u length mismatch"
				      " (expect = %u, actual = %u)\n", i,
				      rtp_len, mbv_native.mbv[i]->end);
			break;
		}
		if (0 != memcmp(payload,
				&mbv_native.mbv[i]->buf[hdr_len],
				payload_len)) {
			err = EBADMSG;
			DEBUG_WARNING("RTP packet %u content mismatch\n", i);

			test_hexdump_dual(stderr,
					  payload,
					  payload_len,
					  &mbv_native.mbv[i]->buf[hdr_len],
					  mbv_native.mbv[i]->end - hdr_len);
			break;
		}

		if (verbose) {
			re_printf("RTP packet OK\n");
		}
	}
	if (!err)
		re_printf("verified %u RTP-packets ok\n", i);

 out:
	mbv_reset(&mbv_native);
	mbv_reset(&mbv_libsrtp);
	mem_deref(payload);

	libre_close();
	mem_debug();

	return err;
}
