/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 - 2022 Alfred E. Heggestad
 */

#include <srtp2/srtp.h>
#include <srtp2/crypto_types.h>
#include <openssl/crypto.h>
#include <string.h>
#include <getopt.h>
#include <math.h>
#include <re.h>
#include "core.h"


#define DEBUG_MODULE "srtperf"
#define DEBUG_LEVEL 6
#include <re_dbg.h>


#define MAX_KEY_LEN  32
#define MAX_SALT_LEN 14


struct param {
	uint16_t seq_init;
	size_t master_key_len;    /* bytes, excl. Salt */
};

struct packets {
	struct mbuf **mbv;
	size_t num;
	size_t rtp_hdr_len;
	size_t payload_len;
	size_t rtp_packet_len;
	size_t srtp_packet_len;
};

struct timing {
	double pps;  /* Packets per second */
};

static const uint32_t DUMMY_SSRC = 0x01020304;


/* 128 - 256 bits key */
static const uint8_t master_key[MAX_KEY_LEN + MAX_SALT_LEN] = {
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,
	0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22, 0x22,

	0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
	0x44, 0x44, 0x44, 0x44, 0x44, 0x44, 0x44,
};


static size_t get_taglen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 4;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 10;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 4;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 10;
	case SRTP_AES_128_GCM:             return 16;
	case SRTP_AES_256_GCM:             return 16;
	default: return 0;
	}
}


static int packets_init(const struct param *prm,
			struct packets *mbv, unsigned num,
			const uint8_t *payload, unsigned payload_len,
			enum srtp_suite suite)
{
	struct rtp_header hdr = {
		.ver  = RTP_VERSION,
		.ssrc = DUMMY_SSRC
	};
	uint16_t seq = prm->seq_init;
	size_t tag_len = get_taglen(suite);
	int err = 0;

	mbv->mbv = mem_zalloc(num * sizeof(struct mbuf *), NULL);
	if (!mbv->mbv)
		return ENOMEM;

	mbv->num = num;
	mbv->rtp_hdr_len = RTP_HEADER_SIZE + hdr.cc*4;
	mbv->payload_len = payload_len;
	mbv->rtp_packet_len = mbv->rtp_hdr_len + payload_len;
	mbv->srtp_packet_len = mbv->rtp_hdr_len + payload_len + tag_len;

	for (unsigned i=0; i<num; i++) {

		size_t len = mbv->rtp_packet_len + 16;  /* max trailer */

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
	for (unsigned i=0; i<mbv->num; i++)
		mem_deref(mbv->mbv[i]);

	mem_deref(mbv->mbv);
}


static size_t get_saltlen(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return 14;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return 14;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return 14;
	case SRTP_AES_128_GCM:             return 12;
	case SRTP_AES_256_GCM:             return 12;
	default: return 0;
	}
}


static bool suite_is_gcm(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return false;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return false;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return false;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return false;
	case SRTP_AES_128_GCM:             return true;
	case SRTP_AES_256_GCM:             return true;
	default: return false;
	}
}


static uint32_t get_libsrtp_cipher(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return SRTP_AES_ICM_128;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return SRTP_AES_ICM_128;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return SRTP_AES_ICM_256;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return SRTP_AES_ICM_256;
	case SRTP_AES_128_GCM:             return SRTP_AES_GCM_128;
	case SRTP_AES_256_GCM:             return SRTP_AES_GCM_256;
	default: return 0;
	}
}


static uint32_t get_libsrtp_auth(enum srtp_suite suite)
{
	switch (suite) {

	case SRTP_AES_CM_128_HMAC_SHA1_32: return SRTP_HMAC_SHA1;
	case SRTP_AES_CM_128_HMAC_SHA1_80: return SRTP_HMAC_SHA1;
	case SRTP_AES_256_CM_HMAC_SHA1_32: return SRTP_HMAC_SHA1;
	case SRTP_AES_256_CM_HMAC_SHA1_80: return SRTP_HMAC_SHA1;
	case SRTP_AES_128_GCM:             return SRTP_NULL_AUTH;
	case SRTP_AES_256_GCM:             return SRTP_NULL_AUTH;
	default: return 0;
	}
}


static int perftest_libsrtp_encode(const struct param *prm,
				   struct packets *mbv, enum srtp_suite suite)
{
	srtp_t srtp = 0;
	srtp_policy_t policy_tx;
	srtp_crypto_policy_t policy;
	srtp_err_status_t e;
	const int exp_len = (int)(mbv->srtp_packet_len);
	int len, err = 0;
	size_t salt_len = get_saltlen(suite);

	memset(&policy, 0, sizeof(policy));
	policy.cipher_type     = get_libsrtp_cipher(suite);
	policy.cipher_key_len  = (int)(prm->master_key_len + salt_len);
	policy.auth_type       = get_libsrtp_auth(suite);
	policy.auth_key_len    = suite_is_gcm(suite) ? 0 : 20;
	policy.auth_tag_len    = (int)get_taglen(suite);
	policy.sec_serv        = sec_serv_conf | sec_serv_auth;

	memset(&policy_tx, 0, sizeof(policy_tx));
	policy_tx.rtp = policy;
	policy_tx.rtcp = policy;
	policy_tx.ssrc.type = ssrc_any_outbound;
	policy_tx.key = (uint8_t *)master_key;
	policy_tx.next = NULL;

	e = srtp_create(&srtp, &policy_tx);
	if (e != srtp_err_status_ok) {
		DEBUG_WARNING("enc: srtp_create failed (e=%d)\n", e);
		err = EPROTO;
		goto out;
	}

	for (size_t i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;
		mb->end = mbv->rtp_packet_len;

		len = (int)mbuf_get_left(mb);

		e = srtp_protect(srtp, mbuf_buf(mb), &len);
		if (srtp_err_status_ok != e) {
			DEBUG_WARNING("libsrtp: srtp_protect: e = %d\n", e);
			err = EPROTO;
			break;
		}
		if (len != exp_len) {
			DEBUG_WARNING("libsrtp: len: expect %d, got %d\n",
				      exp_len, len);
			err = EPROTO;
			break;
		}
		mb->end = len;
	}

 out:
	if (srtp)
		srtp_dealloc(srtp);

	return err;
}


static int perftest_libsrtp_decode(const struct param *prm,
				   struct packets *mbv, enum srtp_suite suite)
{
	srtp_t srtp = 0;
	srtp_policy_t policy_rx;
	srtp_crypto_policy_t policy;
	srtp_err_status_t e;
	const int exp_len_rtp = (int)mbv->rtp_packet_len;
	size_t salt_len = get_saltlen(suite);
	int len, err = 0;

	memset(&policy, 0, sizeof(policy));
	policy.cipher_type     = get_libsrtp_cipher(suite);
	policy.cipher_key_len  = (int)(prm->master_key_len + salt_len);
	policy.auth_type       = get_libsrtp_auth(suite);
	policy.auth_key_len    = suite_is_gcm(suite) ? 0 : 20;
	policy.auth_tag_len    = (int)get_taglen(suite);
	policy.sec_serv        = sec_serv_conf;
	policy.sec_serv       |= sec_serv_auth;

	memset(&policy_rx, 0, sizeof(policy_rx));
	policy_rx.rtp = policy;
	policy_rx.rtcp = policy;
	policy_rx.ssrc.type = ssrc_any_inbound;
	policy_rx.key = (uint8_t *)master_key;
	policy_rx.next = NULL;

	e = srtp_create(&srtp, &policy_rx);
	if (e != srtp_err_status_ok) {
		DEBUG_WARNING("dec: srtp_create failed (e=%d)\n", e);
		err = EPROTO;
		goto out;
	}

	for (size_t i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;

		len = (int)mbuf_get_left(mb);

		e = srtp_unprotect(srtp, mbuf_buf(mb), &len);
		if (srtp_err_status_ok != e) {
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
	if (srtp)
		srtp_dealloc(srtp);

	return err;
}


static int perftest_native_encode(const struct param *prm,
				  struct packets *mbv, enum srtp_suite suite)
{
	struct srtp *ctx = NULL;
	size_t salt_len = get_saltlen(suite);
	int err;

	err = srtp_alloc(&ctx, suite, master_key,
			 prm->master_key_len + salt_len,
			 0);
	if (err) {
		DEBUG_WARNING("srtp_alloc failed: %m\n", err);
		goto out;
	}

	for (size_t i=0; i<mbv->num; i++) {

		struct mbuf *mb = mbv->mbv[i];

		mb->pos = 0;
		mb->end = mbv->rtp_packet_len;

		err = srtp_encrypt(ctx, mb);
		if (err)
			break;
		if (mb->end != mbv->srtp_packet_len) {
			DEBUG_WARNING("native: encode: i=%u"
				      " length mismatch"
				      " (expected=%zu, mb=%zu)\n",
				      i, mbv->srtp_packet_len, mb->end);
			err = EPROTO;
			break;
		}
	}

 out:
	mem_deref(ctx);

	return err;
}


static int perftest_native_decode(const struct param *prm,
				  struct packets *mbv, enum srtp_suite suite)
{
	struct srtp *ctx = NULL;
	size_t salt_len = get_saltlen(suite);
	int err;

	err = srtp_alloc(&ctx, suite, master_key,
			 prm->master_key_len + salt_len,
			 0);
	if (err)
		goto out;

	for (size_t i=0; i<mbv->num; i++) {

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


static enum srtp_suite resolve_suite(unsigned master_key_len,
				     unsigned auth_bits)
{
	enum srtp_suite suite;

	if (master_key_len == 16 && auth_bits == 32)
		suite = SRTP_AES_CM_128_HMAC_SHA1_32;
	else if (master_key_len == 16 && auth_bits == 80)
		suite = SRTP_AES_CM_128_HMAC_SHA1_80;
	else if (master_key_len == 32 && auth_bits == 32)
		suite = SRTP_AES_256_CM_HMAC_SHA1_32;
	else if (master_key_len == 32 && auth_bits == 80)
		suite = SRTP_AES_256_CM_HMAC_SHA1_80;
	else if (master_key_len == 16 && auth_bits == 0)
		suite = SRTP_AES_128_GCM;
	else if (master_key_len == 32 && auth_bits == 0)
		suite = SRTP_AES_256_GCM;
	else {
		return (enum srtp_suite)-1;
	}

	return suite;
}


static int execute_encrypt(const struct param *prm,
			   struct packets *mbv_libsrtp,
			   struct packets *mbv_native,
			   enum srtp_suite suite,
			   struct timing *timing_srtp,
			   struct timing *timing_native)
{
	uint64_t t0, t1, t2;
	int err = 0;

	t0 = tmr_jiffies_usec();
	err = perftest_libsrtp_encode(prm, mbv_libsrtp, suite);
	if (err) {
		re_fprintf(stderr, "perftest_libsrtp_encode failed: %m\n",
			   err);
		goto out;
	}
	t1 = tmr_jiffies_usec();
	err = perftest_native_encode(prm, mbv_native, suite);
	t2 = tmr_jiffies_usec();
	if (err) {
		re_fprintf(stderr, "perftest_native_encode failed: %m\n", err);
		goto out;
	}

	re_printf("libsrtp encrypt %u times:    %d usec\n",
		  mbv_libsrtp->num, (int)(t1-t0));
	re_printf("native  encrypt %u times:    %d usec   (%.1f %%)\n",
		  mbv_native->num, (int)(t2-t1),
		  100.0 * ((int)(t2-t1) - (int)(t1-t0)) / (t1-t0) );

	double pps_srtp = 1000000LL * mbv_libsrtp->num / (double)(t1-t0);
	double pps_native = 1000000LL * mbv_native->num / (double)(t2-t1);

	re_printf("libsrtp packets per. second:   %.1f\n", pps_srtp);
	re_printf("native packets per. second:    %.1f\n", pps_native);

	if (timing_srtp)
		timing_srtp->pps = pps_srtp;
	if (timing_native)
		timing_native->pps = pps_native;

 out:
	return err;
}


static int verify_encrypt(const struct packets *mbv_libsrtp,
			  const struct packets *mbv_native)
{
	int err = 0;

	/* compare all SRTP packets */
	for (size_t i=0; i<mbv_libsrtp->num; i++) {

		if (mbv_libsrtp->mbv[i]->end !=
		    mbv_native->mbv[i]->end) {
			err = EBADMSG;
			DEBUG_WARNING("SRTP packet %u length mismatch"
				      " (libsrtp = %u, native = %u)\n", i,
				      mbv_libsrtp->mbv[i]->end,
				      mbv_native->mbv[i]->end);
			break;
		}
		if (0 != memcmp(mbv_libsrtp->mbv[i]->buf,
				mbv_native->mbv[i]->buf,
				mbv_libsrtp->mbv[i]->end)) {
			err = EBADMSG;
			DEBUG_WARNING("SRTP packet %u content mismatch\n", i);

			hexdump_dual(stderr,
					  mbv_libsrtp->mbv[i]->buf,
					  mbv_libsrtp->mbv[i]->end,
					  mbv_native->mbv[i]->buf,
					  mbv_native->mbv[i]->end);
			break;
		}
	}
	if (!err)
		re_printf("verified encrypt %u SRTP-packets ok\n",
			  mbv_libsrtp->num);

	return err;
}


static int execute_decrypt(const struct param *prm,
			   struct packets *mbv_libsrtp,
			   struct packets *mbv_native,
			   enum srtp_suite suite)
{
	uint64_t t0, t1, t2;
	int64_t delta_libsrtp, delta_native;
	double percent;
	int err = 0;

	t0 = tmr_jiffies_usec();
	err = perftest_libsrtp_decode(prm, mbv_libsrtp, suite);
	if (err) {
		re_fprintf(stderr, "perftest_libsrtp_decode failed:"
			   " %m\n", err);
		goto out;
	}
	t1 = tmr_jiffies_usec();
	err = perftest_native_decode(prm, mbv_native, suite);
	t2 = tmr_jiffies_usec();
	if (err) {
		re_fprintf(stderr, "perftest_native_decode failed: %m\n", err);
		goto out;
	}

	delta_libsrtp = t1 - t0;
	delta_native  = t2 - t1;
	percent = 100.0f * (delta_native - delta_libsrtp) / (delta_libsrtp);

	/* show timing */
	re_printf("libsrtp decrypt %u times:    %lli usec\n",
		  mbv_libsrtp->num, delta_libsrtp);
	re_printf("native  decrypt %u times:    %lli usec   (%.1f %%)\n",
		  mbv_native->num, delta_native, percent);

 out:
	return err;
}


static int verify_decrypt(const uint8_t *payload, size_t payload_len,
			  const struct packets *mbv_native)
{
	int err = 0;

	/* verify all decrypted RTP-packets */
	for (size_t i=0; i<mbv_native->num; i++) {

		size_t hdr_len = mbv_native->rtp_hdr_len;
		size_t rtp_len = mbv_native->rtp_packet_len;

		if (mbv_native->mbv[i]->end != rtp_len) {
			err = EBADMSG;
			DEBUG_WARNING("RTP packet %u length mismatch"
				      " (expect = %u, actual = %u)\n", i,
				      rtp_len, mbv_native->mbv[i]->end);
			break;
		}
		if (0 != memcmp(payload,
				&mbv_native->mbv[i]->buf[hdr_len],
				payload_len)) {
			err = EBADMSG;
			DEBUG_WARNING("RTP packet %u content mismatch\n", i);

			hexdump_dual(stderr,
				     payload,
				     payload_len,
				     &mbv_native->mbv[i]->buf[hdr_len],
				     mbv_native->mbv[i]->end - hdr_len);
			break;
		}

	}
	if (!err)
		re_printf("verified decrypt %u RTP-packets ok\n",
			  mbv_native->num);

	return err;
}

#define COUNT 15
static const size_t payload_min = 100;
static const size_t payload_max = 1500;
static const size_t payload_interval = 100;
static size_t payloads[COUNT];


static int plot_payloads(const struct param *prm, size_t num,
			 enum srtp_suite suite)
{
	struct packets mbv_libsrtp, mbv_native;

	uint8_t *payload;
	int err = 0;

	struct timing timing_srtp[COUNT];
	struct timing timing_native[COUNT];

	memset(&mbv_libsrtp, 0, sizeof(mbv_libsrtp));
	memset(&mbv_native, 0, sizeof(mbv_native));

	size_t payload_len = payload_min;

	for (size_t i=0; i < COUNT; i++) {

		payloads[i] = payload_len;

		payload = mem_alloc(payload_len, NULL);

		rand_bytes(payload, payload_len);

		err |= packets_init(prm, &mbv_libsrtp, num,
				    payload, payload_len,
				    suite);
		err |= packets_init(prm, &mbv_native, num,
				    payload, payload_len,
				    suite);
		if (err)
			goto out;

		/*
		 * Start timing now
		 */

		err = execute_encrypt(prm, &mbv_libsrtp, &mbv_native, suite,
				      &timing_srtp[i], &timing_native[i]);
		if (err)
			goto out;

		payload = mem_deref(payload);

		mbv_reset(&mbv_native);
		mbv_reset(&mbv_libsrtp);

		payload_len += payload_interval;
		if (payload_len > payload_max)
			break;
	}

	/* Show */

	re_printf("\n");
	re_printf("Payload size, %s/libsrtp (PPS), %s/libre (PPS)\n",
		  srtp_suite_name(suite), srtp_suite_name(suite));

	for (size_t i=0; i<COUNT; i++) {

		re_printf("%zu, %.1f, %.1f\n", payloads[i],
			  timing_srtp[i].pps,
			  timing_native[i].pps);
	}

 out:
	mem_deref(payload);

	return err;
}


static void usage(void)
{
	(void)re_fprintf(stderr,
			 "srtperf -a <bits> -e <bits>"
			 " -n <NUM> -p <bytes> -h\n");
	(void)re_fprintf(stderr, "\t-a <bits>   Authentication bits\n");
	(void)re_fprintf(stderr, "\t-e <bits>   Encryption key bits\n");
	(void)re_fprintf(stderr, "\t-n NUM      Number of rounds in test\n");
	(void)re_fprintf(stderr, "\t-p <bytes>  RTP Payload size in bytes\n");
	(void)re_fprintf(stderr, "\t-h          Show summary of options\n");
	(void)re_fprintf(stderr, "\t-v          Verbose output\n");
	(void)re_fprintf(stderr, "\t-g          Plot a graph with payload"
			" sizes\n");
}


int main(int argc, char *argv[])
{
	unsigned auth_bits = 80, payload_len = 160, num = 100;
	struct packets mbv_libsrtp, mbv_native;
	uint8_t *payload = NULL;
	bool verbose = false;
	enum srtp_suite suite;  /* todo: move to param? */
	struct param param = {
		.seq_init = 1,
		.master_key_len = 16
	};
	bool plot_graph = false;
	int err = 0;

	memset(&mbv_libsrtp, 0, sizeof(mbv_libsrtp));
	memset(&mbv_native, 0, sizeof(mbv_native));

	for (;;) {

		const int c = getopt(argc, argv, "a:e:p:n:hvg");
		if (0 > c)
			break;

		switch (c) {

		case 'a':
			auth_bits = atoi(optarg);
			break;

		case 'e':
			param.master_key_len = atoi(optarg)/8;
			break;

		case 'g':
			plot_graph = true;
			break;

		case 'p':
			payload_len = atoi(optarg);
			break;

		case 'n':
			num = atoi(optarg);
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

	err = libre_init();
	if (err)
		return err;

	re_printf("srtperf -- SRTP performance testing program\n");
	re_printf("parameters:    seq = %u, payload = %u bytes,"
		  " encr_key = %u bits, auth_bits = %u\n",
		  param.seq_init, payload_len,
		  param.master_key_len*8, auth_bits);
	re_printf("build:         %H\n", sys_build_get, 0);
	re_printf("compiler:      %s\n", __VERSION__);
	re_printf("libre:         %s\n", sys_libre_version_get());
	re_printf("os:            %s\n", sys_os_get());
	re_printf("arch:          %s\n", sys_arch_get());

#ifdef USE_OPENSSL
	re_printf("openssl info:  %s\n%s\n",
		  SSLeay_version(SSLEAY_VERSION),
		  SSLeay_version(SSLEAY_CFLAGS));
#endif

	re_printf("libsrtp:       %s\n", srtp_get_version_string());

	re_printf("\n");

	{
		srtp_err_status_t e;
		if (verbose)
			re_printf("initializing libsrtp..\n");

		e = srtp_init();
		if (srtp_err_status_ok != e) {
			DEBUG_WARNING("srtp_init() failed (e=%d)\n", e);
			return ENOSYS;
		}

		if (verbose)
			re_printf("libsrtp initialized OK\n");
	}

	suite = resolve_suite(param.master_key_len, auth_bits);
	if ((int)suite == -1) {
		re_fprintf(stderr, "no matching suite -- invalid parameters"
			   " (master_key = %u bytes, auth_bits = %u)\n",
			   param.master_key_len, auth_bits);
		err = EINVAL;
		goto out;
	}

	re_printf("suite:         %s\n", srtp_suite_name(suite));

	if (plot_graph) {
		err = plot_payloads(&param, num, suite);
		goto out;
	}

	payload = mem_alloc(payload_len, NULL);

	rand_bytes(payload, payload_len);


	if (verbose)
		re_printf("creating %u packets\n", num);
	err |= packets_init(&param, &mbv_libsrtp, num, payload, payload_len,
			    suite);
	err |= packets_init(&param, &mbv_native, num, payload, payload_len,
			    suite);
	if (err)
		goto out;

	/*
	 * Start timing now
	 */
	if (verbose)
		re_printf("starting encryption tests..\n");

	err = execute_encrypt(&param, &mbv_libsrtp, &mbv_native, suite,
			      0,0);
	if (err)
		goto out;

	err = verify_encrypt(&mbv_libsrtp, &mbv_native);
	if (err)
		goto out;

	re_printf("\n");

	err = execute_decrypt(&param, &mbv_libsrtp, &mbv_native, suite);
	if (err)
		goto out;

	err = verify_decrypt(payload, payload_len, &mbv_native);
	if (err)
		goto out;

 out:
	mbv_reset(&mbv_native);
	mbv_reset(&mbv_libsrtp);
	mem_deref(payload);

	libre_close();
	mem_debug();

	return err;
}
