#include "miner.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <stdio.h>


#include "crypto/argon2d/argon2.h"

#define T_COSTS 2
#define M_COSTS 16
#define MASK 8
#define ZERO 0
const uint32_t INPUT_BYTES = 80;  // Lenth of a block header in bytes. Input Length = Salt Length (salt = input)
const uint32_t OUTPUT_BYTES = 32; // Length of output needed for a 256-bit hash
const unsigned int DEFAULT_ARGON2_FLAG = 2; //Same as ARGON2_DEFAULT_FLAGS



void argon2hash(void *output, const void *input)
{
	argon2_context context;
	context.out = (uint8_t *)output;
	context.outlen = (uint32_t)OUTPUT_BYTES;
	context.pwd = (uint8_t *)input;
	context.pwdlen = (uint32_t)INPUT_BYTES;
	context.salt = (uint8_t *)input; //salt = input
	context.saltlen = (uint32_t)INPUT_BYTES;
	context.secret = NULL;
	context.secretlen = 0;
	context.ad = NULL;
	context.adlen = 0;
	context.allocate_cbk = NULL;
	context.free_cbk = NULL;
	context.flags = DEFAULT_ARGON2_FLAG; // = ARGON2_DEFAULT_FLAGS
	// main configurable Argon2 hash parameters
	context.m_cost = 250; // Memory in KiB (~256KB)
	context.lanes = 4;    // Degree of Parallelism
	context.threads = 1;  // Threads
	context.t_cost = 1;   // Iterations

	argon2_ctx(&context, Argon2_d);
	memcpy(output, context.out, 32);
}

int scanhash_argon2(int thr_id, uint32_t *pdata, const uint32_t *ptarget,
	uint32_t max_nonce,	uint64_t *hashes_done, void *ctx)
{
	uint32_t _ALIGN(64) endiandata[20];
	const uint32_t first_nonce = pdata[19];
	uint32_t nonce = first_nonce;


	for (int k = 0; k < 20; k++)
	{
		be32enc(&endiandata[k], ((uint32_t*)pdata)[k]);		
	}

	do {
		const uint32_t Htarg = ptarget[7];
		uint32_t hash[8];

		unsigned char *test = (char*)hash;
		be32enc(&endiandata[19], nonce);

#ifdef __AVX2__
		WolfArgon2dPoWHash(hash, ctx, endiandata);
#else
		argon2hash(hash, endiandata);
#endif
		if (hash[7] <= Htarg && fulltest(hash, ptarget)) {
			pdata[19] = nonce;
			*hashes_done = pdata[19] - first_nonce;
			return 1;
		}
		nonce++;
	} while (nonce < max_nonce && !work_restart[thr_id].restart);

	pdata[19] = nonce;
	*hashes_done = pdata[19] - first_nonce + 1;
	return 0;
}

