/**
 * @file dukpt-tool.c
 * @brief Simple DUKPT tool
 *
 * Copyright (c) 2021 Leon Lynch
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2.1 of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this program. If not, see
 * <https://www.gnu.org/licenses/>.
 */

#include "dukpt_tdes.h"

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <argp.h>

// Globals
static uint8_t* bdk = NULL;
static size_t bdk_len = 0;
static uint8_t* ik = NULL;
static size_t ik_len = 0;
static uint8_t* ksn = NULL;
static size_t ksn_len = 0;
static uint8_t* txn_key = NULL;
static size_t txn_key_len = 0;

enum dukpt_tool_mode_t {
	DUKPT_TOOL_MODE_NONE,
	DUKPT_TOOL_MODE_DERIVE_IK,
	DUKPT_TOOL_MODE_DERIVE_TXN_KEY,
	DUKPT_TOOL_MODE_ADVANCE_KSN,
};
static enum dukpt_tool_mode_t dukpt_tool_mode = DUKPT_TOOL_MODE_NONE;

// Helper functions
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state);
static int parse_hex(const char* hex, void* buf, size_t buf_len);
static void print_hex(const void* buf, size_t length);

// argp option keys
enum dukpt_tool_option_t {
	DUKPT_TOOL_OPTION_BDK,
	DUKPT_TOOL_OPTION_IK,
	DUKPT_TOOL_OPTION_KSN,

	DUKPT_TOOL_OPTION_DERIVE_IK,
	DUKPT_TOOL_OPTION_DERIVE_TXN_KEY,
	DUKPT_TOOL_OPTION_ADVANCE_KSN,
};

// argp option structure
static struct argp_option argp_options[] = {
	{ NULL, 0, NULL, 0, "Inputs:", 1 },
	{ "bdk", DUKPT_TOOL_OPTION_BDK, "BDK", 0, "Base Derivation Key (BDK)" },
	{ "ik", DUKPT_TOOL_OPTION_IK, "IK", 0, "Initial Key (IK)" },
	{ "ipek", DUKPT_TOOL_OPTION_IK, NULL, OPTION_ALIAS },
	{ "ksn", DUKPT_TOOL_OPTION_KSN, "KSN", 0, "Key Serial Number (KSN)" },

	{ NULL, 0, NULL, 0, "Actions:", 2 },
	{ "derive-ik", DUKPT_TOOL_OPTION_DERIVE_IK, NULL, 0, "Derive Initial Key (IK). Requires BDK and KSN." },
	{ "derive-ipek", DUKPT_TOOL_OPTION_DERIVE_IK, NULL, OPTION_ALIAS },
	{ "derive-txn-key", DUKPT_TOOL_OPTION_DERIVE_TXN_KEY, NULL, 0, "Derive transaction key. Requires either BDK or IK, as well as KSN." },
	{ "advance-ksn", DUKPT_TOOL_OPTION_ADVANCE_KSN, NULL, 0, "Advance to next valid KSN. Requires KSN." },

	{ 0, 0, NULL, 0, "All argument values are strings of hex digits representing binary data" },
	{ 0 },
};

// argp configuration
static struct argp argp_config = {
	argp_options,
	argp_parser_helper,
};

// argp parser helper function
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state)
{
	int r;
	uint8_t* buf = 0;
	size_t buf_len = 0;

	if (arg) {
		size_t arg_len = strlen(arg);

		if (arg_len % 2 != 0) {
			argp_error(state, "Argument value must have even number of digits");
		}

		buf_len = arg_len / 2;
		buf = malloc(buf_len);

		r = parse_hex(arg, buf, buf_len);
		if (r) {
			argp_error(state, "Argument value must consist of hex digits");
		}
	}

	switch (key) {
		case DUKPT_TOOL_OPTION_BDK:
			bdk = buf;
			bdk_len = buf_len;
			return 0;

		case DUKPT_TOOL_OPTION_IK:
			ik = buf;
			ik_len = buf_len;
			return 0;

		case DUKPT_TOOL_OPTION_KSN:
			ksn = buf;
			ksn_len = buf_len;
			return 0;

		case DUKPT_TOOL_OPTION_DERIVE_IK:
			dukpt_tool_mode = DUKPT_TOOL_MODE_DERIVE_IK;
			return 0;

		case DUKPT_TOOL_OPTION_DERIVE_TXN_KEY:
			dukpt_tool_mode = DUKPT_TOOL_MODE_DERIVE_TXN_KEY;
			return 0;

		case DUKPT_TOOL_OPTION_ADVANCE_KSN:
			dukpt_tool_mode = DUKPT_TOOL_MODE_ADVANCE_KSN;
			return 0;

		default:
			return ARGP_ERR_UNKNOWN;
	}
}

// Hex parser helper function
static int parse_hex(const char* hex, void* buf, size_t buf_len)
{
	size_t hex_len = buf_len * 2;

	for (size_t i = 0; i < hex_len; ++i) {
		if (!isxdigit(hex[i])) {
			return -1;
		}
	}

	while (*hex && buf_len--) {
		uint8_t* ptr = buf;

		char str[3];
		strncpy(str, hex, 2);
		str[2] = 0;

		*ptr = strtoul(str, NULL, 16);

		hex += 2;
		++buf;
	}

	return 0;
}

// Hex output helper function
static void print_hex(const void* buf, size_t length)
{
	const uint8_t* ptr = buf;
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

int main(int argc, char** argv)
{
	int r;

	if (argc == 1) {
		// No command line arguments
		argp_help(&argp_config, stdout, ARGP_HELP_STD_HELP, argv[0]);
		return 1;
	}

	r = argp_parse(&argp_config, argc, argv, 0, 0, 0);
	if (r) {
		fprintf(stderr, "Failed to parse command line\n");
		return 1;
	}

	switch (dukpt_tool_mode) {
		case DUKPT_TOOL_MODE_NONE: {
			// No command line arguments
			argp_help(&argp_config, stdout, ARGP_HELP_STD_HELP, argv[0]);
			break;
		}

		case DUKPT_TOOL_MODE_DERIVE_IK:
			// Validate required inputs
			if (!bdk) {
				fprintf(stderr, "BDK is required to derive IK\n");
				r = 1;
				goto exit;
			}
			if (!ksn) {
				fprintf(stderr, "KSN is required to derive IK\n");
				r = 1;
				goto exit;
			}

			// Validate BDK length
			if (bdk_len != DUKPT_TDES_KEY_LEN) {
				fprintf(stderr, "BDK must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KEY_LEN, DUKPT_TDES_KEY_LEN * 2);
				r = 1;
				goto exit;
			}

			// Validate KSN length
			if (ksn_len != DUKPT_TDES_KSN_LEN) {
				fprintf(stderr, "KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2);
				r = 1;
				goto exit;
			}

			ik_len = DUKPT_TDES_KEY_LEN;
			ik = malloc(ik_len);

			// Do it
			r = dukpt_tdes_derive_ik(bdk, ksn, ik);
			if (r) {
				fprintf(stderr, "dukpt_tdes_derive_ik() failed; r=%d\n", r);
				goto exit;
			}
			print_hex(ik, ik_len);
			break;

		case DUKPT_TOOL_MODE_DERIVE_TXN_KEY:
			// Validate required inputs
			if (!bdk && !ik) {
				fprintf(stderr, "Either BDK or IK is required to derive transaction key\n");
				r = 1;
				goto exit;
			}
			if (!ksn) {
				fprintf(stderr, "KSN is required to derive transaction key\n");
				r = 1;
				goto exit;
			}

			// Validate KSN length
			if (ksn_len != DUKPT_TDES_KSN_LEN) {
				fprintf(stderr, "KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2);
				r = 1;
				goto exit;
			}

			// If IK is not available, derive it
			if (!ik) {
				// Validate BDK length
				if (bdk_len != DUKPT_TDES_KEY_LEN) {
					fprintf(stderr, "BDK must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KEY_LEN, DUKPT_TDES_KEY_LEN * 2);
					r = 1;
					goto exit;
				}

				ik_len = DUKPT_TDES_KEY_LEN;
				ik = malloc(ik_len);

				r = dukpt_tdes_derive_ik(bdk, ksn, ik);
				if (r) {
					fprintf(stderr, "dukpt_tdes_derive_ik() failed; r=%d\n", r);
					goto exit;
				}
			}

			txn_key_len = DUKPT_TDES_KEY_LEN;
			txn_key = malloc(txn_key_len);

			// Do it
			r = dukpt_tdes_derive_txn_key(ik, ksn, txn_key);
			if (r) {
				fprintf(stderr, "dukpt_tdes_derive_txn_key() failed; r=%d\n", r);
				goto exit;
			}
			print_hex(txn_key, txn_key_len);
			break;

		case DUKPT_TOOL_MODE_ADVANCE_KSN:
			// Validate required inputs
			if (!ksn) {
				fprintf(stderr, "KSN is required to advance to next valid KSN\n");
				r = 1;
				goto exit;
			}

			// Validate KSN length
			if (ksn_len != DUKPT_TDES_KSN_LEN) {
				fprintf(stderr, "KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2);
				r = 1;
				goto exit;
			}

			// Advance to the next transaction
			r = dukpt_tdes_ksn_advance(ksn);
			if (r < 0) {
				fprintf(stderr, "dukpt_tdes_ksn_advance() failed; r=%d\n", r);
				goto exit;
			}
			if (r > 0) {
				fprintf(stderr, "KSN exhausted\n");
				goto exit;
			}

			print_hex(ksn, ksn_len);
			break;
	}

exit:
	if (bdk) {
		free(bdk);
		bdk = NULL;
		bdk_len = 0;
	}
	if (ik) {
		free(ik);
		ik = NULL;
		ik_len = 0;
	}
	if (ksn) {
		free(ksn);
		ksn = NULL;
		ksn_len = 0;
	}
	if (txn_key) {
		free(txn_key);
		txn_key = NULL;
		txn_key_len = 0;
	}

	return r;
}
