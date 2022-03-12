/**
 * @file dukpt-tool.c
 * @brief Simple DUKPT tool
 *
 * Copyright (c) 2021, 2022 Leon Lynch
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
#include "dukpt_aes.h"

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
static enum dukpt_aes_key_type_t key_type;
static bool key_type_valid = false;
static void* pinblock = NULL;
static size_t pinblock_len = 0;
static void* panblock = NULL;
static size_t panblock_len = 0;
static void* txn_data = NULL;
static size_t txn_data_len = 0;
static void* iv = NULL;
static size_t iv_len = 0;

static bool found_stdin_arg = false;

enum dukpt_tool_mode_t {
	DUKPT_TOOL_MODE_TDES,
	DUKPT_TOOL_MODE_AES,
};
static enum dukpt_tool_mode_t dukpt_tool_mode = DUKPT_TOOL_MODE_TDES;

enum dukpt_tool_action_t {
	DUKPT_TOOL_ACTION_NONE,
	DUKPT_TOOL_ACTION_DERIVE_IK,
	DUKPT_TOOL_ACTION_DERIVE_TXN_KEY,
	DUKPT_TOOL_ACTION_ADVANCE_KSN,
	DUKPT_TOOL_ACTION_DERIVE_UPDATE_KEY,
	DUKPT_TOOL_ACTION_ENCRYPT_PINBLOCK,
	DUKPT_TOOL_ACTION_DECRYPT_PINBLOCK,
	DUKPT_TOOL_ACTION_ENCRYPT_REQUEST,
	DUKPT_TOOL_ACTION_DECRYPT_REQUEST,
	DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE,
	DUKPT_TOOL_ACTION_DECRYPT_RESPONSE,
};
static enum dukpt_tool_action_t dukpt_tool_action = DUKPT_TOOL_ACTION_NONE;

enum dukpt_tool_output_format_t {
	DUKPT_TOOL_OUTPUT_FORMAT_HEX,
	DUKPT_TOOL_OUTPUT_FORMAT_RAW,
};
static enum dukpt_tool_output_format_t output_format = DUKPT_TOOL_OUTPUT_FORMAT_HEX;

// Helper functions
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state);
static int parse_hex(const char* hex, void* buf, size_t* buf_len);
static void* read_file(FILE* file, size_t* len);
static void output_buf(const void* buf, size_t length);

// argp option keys
enum dukpt_tool_option_t {
	DUKPT_TOOL_OPTION_MODE = 1,
	DUKPT_TOOL_OPTION_KEY_TYPE,

	DUKPT_TOOL_OPTION_BDK,
	DUKPT_TOOL_OPTION_IK,
	DUKPT_TOOL_OPTION_KSN,
	DUKPT_TOOL_OPTION_PANBLOCK,
	DUKPT_TOOL_OPTION_IV,

	DUKPT_TOOL_OPTION_DERIVE_IK,
	DUKPT_TOOL_OPTION_DERIVE_TXN_KEY,
	DUKPT_TOOL_OPTION_ADVANCE_KSN,
	DUKPT_TOOL_OPTION_DERIVE_UPDATE_KEY,

	DUKPT_TOOL_OPTION_ENCRYPT_PINBLOCK,
	DUKPT_TOOL_OPTION_DECRYPT_PINBLOCK,

	DUKPT_TOOL_OPTION_ENCRYPT_REQUEST,
	DUKPT_TOOL_OPTION_DECRYPT_REQUEST,
	DUKPT_TOOL_OPTION_ENCRYPT_RESPONSE,
	DUKPT_TOOL_OPTION_DECRYPT_RESPONSE,

	DUKPT_TOOL_OPTION_OUTPUT_RAW,
};

// argp option structure
static struct argp_option argp_options[] = {
	{ NULL, 0, NULL, 0, "Derivation mode:", 1 },
	{ "mode", DUKPT_TOOL_OPTION_MODE, "TDES|AES", 0, "Derivation mode. Default is TDES." },

	{ NULL, 0, NULL, 0, "AES working key:", 2 },
	{ "key-type", DUKPT_TOOL_OPTION_KEY_TYPE, "AES128|AES192|AES256", 0, "Working key type. Only applies to AES derivation mode. Defaults to length of BDK or IK." },

	{ NULL, 0, NULL, 0, "Inputs:", 3 },
	{ "bdk", DUKPT_TOOL_OPTION_BDK, "KEY", 0, "Base Derivation Key (BDK)" },
	{ "ik", DUKPT_TOOL_OPTION_IK, "KEY", 0, "Initial Key (IK)" },
	{ "ipek", DUKPT_TOOL_OPTION_IK, NULL, OPTION_ALIAS },
	{ "ksn", DUKPT_TOOL_OPTION_KSN, "HEX", 0, "Key Serial Number (KSN)" },
	{ "panblock", DUKPT_TOOL_OPTION_PANBLOCK, "HEX", 0, "Encoded PAN block used for AES PIN block encryption/decryption." },
	{ "iv", DUKPT_TOOL_OPTION_IV, "HEX", 0, "Initial vector used for encryption/decryption. Default is a zero buffer." },

	{ NULL, 0, NULL, 0, "Actions:", 4 },
	{ "derive-ik", DUKPT_TOOL_OPTION_DERIVE_IK, NULL, 0, "Derive Initial Key (IK). Requires BDK and KSN." },
	{ "derive-ipek", DUKPT_TOOL_OPTION_DERIVE_IK, NULL, OPTION_ALIAS },
	{ "derive-txn-key", DUKPT_TOOL_OPTION_DERIVE_TXN_KEY, NULL, 0, "Derive transaction key. Requires either BDK or IK, as well as KSN." },
	{ "advance-ksn", DUKPT_TOOL_OPTION_ADVANCE_KSN, NULL, 0, "Advance to next valid KSN. Requires KSN. Non-zero exit status if current or next KSN is invalid." },
	{ "derive-update-key", DUKPT_TOOL_OPTION_DERIVE_UPDATE_KEY, NULL, 0, "Derive DUKPT update key. Requires either BDK or IK, as well as KSN." },
	{ "encrypt-pinblock", DUKPT_TOOL_OPTION_ENCRYPT_PINBLOCK, "DATA", 0, "Encrypt PIN block. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },
	{ "decrypt-pinblock", DUKPT_TOOL_OPTION_DECRYPT_PINBLOCK, "DATA", 0, "Decrypt PIN block. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },
	{ "encrypt-request", DUKPT_TOOL_OPTION_ENCRYPT_REQUEST, "DATA", 0, "Encrypt transaction request data. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },
	{ "decrypt-request", DUKPT_TOOL_OPTION_DECRYPT_REQUEST, "DATA", 0, "Decrypt transaction request data. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },
	{ "encrypt-response", DUKPT_TOOL_OPTION_ENCRYPT_RESPONSE, "DATA", 0, "Encrypt transaction response data. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },
	{ "decrypt-response", DUKPT_TOOL_OPTION_DECRYPT_RESPONSE, "DATA", 0, "Decrypt transaction response data. Requires either BDK or IK, as well as KSN. Use - to read raw bytes from stdin." },

	{ NULL, 0, NULL, 0, "Outputs:", 5 },
	{ "output-raw", DUKPT_TOOL_OPTION_OUTPUT_RAW, NULL, 0, "Output raw bytes instead of hex digits to stdout." },

	{ 0 },
};

// argp configuration
static struct argp argp_config = {
	argp_options,
	argp_parser_helper,
	0,
	" \v" // Force the text to be after the options in the help message
	"Use derivation mode TDES for ANSI X9.24-1:2009 TDES DUKPT.\n"
	"Use derivation mode AES for ANSI X9.24-3:2017 AES DUKPT.\n"
	"\n"
	"KEY and HEX argument values are strings of hex digits representing binary data.\n"
	"DATA argument values are strings of hex digits representing binary data, or - to read raw bytes from stdin.\n"
};

// argp parser helper function
static error_t argp_parser_helper(int key, char* arg, struct argp_state* state)
{
	int r;
	uint8_t* buf = 0;
	size_t buf_len = 0;

	if (arg) {
		// Process option argument
		switch (key) {
			case DUKPT_TOOL_OPTION_ENCRYPT_PINBLOCK:
			case DUKPT_TOOL_OPTION_DECRYPT_PINBLOCK:
			case DUKPT_TOOL_OPTION_ENCRYPT_REQUEST:
			case DUKPT_TOOL_OPTION_DECRYPT_REQUEST:
			case DUKPT_TOOL_OPTION_ENCRYPT_RESPONSE:
			case DUKPT_TOOL_OPTION_DECRYPT_RESPONSE: {
				// If argument is "-", read from stdin
				if (strcmp(arg, "-") == 0) {
					if (found_stdin_arg) {
						argp_error(state, "Only one option may be read from stdin");
					}
					found_stdin_arg = true;

					buf = read_file(stdin, &buf_len);
					if (!buf) {
						argp_error(state, "Failed to read data from stdin");
					}

					break;
				}

				// Intentional fallthrough
			}

			case DUKPT_TOOL_OPTION_BDK:
			case DUKPT_TOOL_OPTION_IK:
			case DUKPT_TOOL_OPTION_KSN:
			case DUKPT_TOOL_OPTION_PANBLOCK:
			case DUKPT_TOOL_OPTION_IV: {
				// Parse arguments as hex data
				size_t arg_len = strlen(arg);

				if (arg_len < 2) {
					argp_error(state, "Argument value must consist of at least 1 bytes (thus 2 hex digits)");
				}

				buf_len = arg_len / 2;
				buf = malloc(buf_len);

				r = parse_hex(arg, buf, &buf_len);
				if (r) {
					argp_error(state, "Argument value must consist of hex digits");
				}

				break;
			}
		}
	}

	switch (key) {
		case DUKPT_TOOL_OPTION_MODE:
			if (strcmp(arg, "TDES") == 0) {
				dukpt_tool_mode = DUKPT_TOOL_MODE_TDES;
			} else if (strcmp(arg, "AES") == 0) {
				dukpt_tool_mode = DUKPT_TOOL_MODE_AES;
			} else {
				argp_error(state, "Invalid derivation mode (--mode) \"%s\"", arg);
			}

			return 0;

		case DUKPT_TOOL_OPTION_KEY_TYPE:
			if (strcmp(arg, "AES128") == 0) {
				key_type = DUKPT_AES_KEY_TYPE_AES128;
			} else if (strcmp(arg, "AES192") == 0) {
				key_type = DUKPT_AES_KEY_TYPE_AES192;
			} else if (strcmp(arg, "AES256") == 0) {
				key_type = DUKPT_AES_KEY_TYPE_AES256;
			} else {
				argp_error(state, "Invalid working key type (--key-type) \"%s\"", arg);
			}

			key_type_valid = true;
			return 0;

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

		case DUKPT_TOOL_OPTION_PANBLOCK:
			panblock = buf;
			panblock_len = buf_len;
			return 0;

		case DUKPT_TOOL_OPTION_IV:
			iv = buf;
			iv_len = buf_len;
			return 0;

		case DUKPT_TOOL_OPTION_DERIVE_IK:
			dukpt_tool_action = DUKPT_TOOL_ACTION_DERIVE_IK;
			return 0;

		case DUKPT_TOOL_OPTION_DERIVE_TXN_KEY:
			dukpt_tool_action = DUKPT_TOOL_ACTION_DERIVE_TXN_KEY;
			return 0;

		case DUKPT_TOOL_OPTION_ADVANCE_KSN:
			dukpt_tool_action = DUKPT_TOOL_ACTION_ADVANCE_KSN;
			return 0;

		case DUKPT_TOOL_OPTION_DERIVE_UPDATE_KEY:
			dukpt_tool_action = DUKPT_TOOL_ACTION_DERIVE_UPDATE_KEY;
			return 0;

		case DUKPT_TOOL_OPTION_ENCRYPT_PINBLOCK:
			pinblock = buf;
			pinblock_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_ENCRYPT_PINBLOCK;
			return 0;

		case DUKPT_TOOL_OPTION_DECRYPT_PINBLOCK:
			pinblock = buf;
			pinblock_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_DECRYPT_PINBLOCK;
			return 0;

		case DUKPT_TOOL_OPTION_ENCRYPT_REQUEST:
			txn_data = buf;
			txn_data_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_ENCRYPT_REQUEST;
			return 0;

		case DUKPT_TOOL_OPTION_DECRYPT_REQUEST:
			txn_data = buf;
			txn_data_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_DECRYPT_REQUEST;
			return 0;

		case DUKPT_TOOL_OPTION_ENCRYPT_RESPONSE:
			txn_data = buf;
			txn_data_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE;
			return 0;

		case DUKPT_TOOL_OPTION_DECRYPT_RESPONSE:
			txn_data = buf;
			txn_data_len = buf_len;
			dukpt_tool_action = DUKPT_TOOL_ACTION_DECRYPT_RESPONSE;
			return 0;

		case DUKPT_TOOL_OPTION_OUTPUT_RAW:
			output_format = DUKPT_TOOL_OUTPUT_FORMAT_RAW;
			return 0;

		case ARGP_KEY_END:
			// Validate options
			if (dukpt_tool_action == DUKPT_TOOL_ACTION_NONE) {
				argp_error(state, "No action specified");
			}
			if (!ksn) {
				argp_error(state, "Key serial number (--ksn) is required");
			}
			if (dukpt_tool_action == DUKPT_TOOL_ACTION_DERIVE_IK &&
				(!bdk || ik)
			) {
				argp_error(state, "Initial key derivation (--derive-ik/--derive-ipek) requires Base Derivation Key (--bdk)");
			}
			if (dukpt_tool_action == DUKPT_TOOL_ACTION_DERIVE_TXN_KEY &&
				((!bdk && !ik) || (bdk && ik))
			) {
				argp_error(state, "Transaction key derivation (--derive-txn-key) requires either Base Derivation Key (--bdk) or Initial Key (--ik)");
			}
			if (dukpt_tool_action == DUKPT_TOOL_ACTION_DERIVE_UPDATE_KEY) {
				if (dukpt_tool_mode != DUKPT_TOOL_MODE_AES) {
					argp_error(state, "Update key derivation (--derive-update-key) is only allowed for derivation mode (--mode) AES");
				}
				if ((!bdk && !ik) || (bdk && ik)) {
					argp_error(state, "Update key derivation (--derive-update-key) requires either Base Derivation Key (--bdk) or Initial Key (--ik)");
				}
			}

			if (dukpt_tool_action == DUKPT_TOOL_ACTION_ENCRYPT_PINBLOCK || dukpt_tool_action == DUKPT_TOOL_ACTION_DECRYPT_PINBLOCK) {
				if (dukpt_tool_mode == DUKPT_TOOL_MODE_TDES && panblock_len != 0) {
					argp_error(state, "PIN block encrypt/decrypt using derivation mode (--mode) TDES assume PAN block is already encoded in PIN block and should not be specified separately");
				}
				if (dukpt_tool_mode == DUKPT_TOOL_MODE_AES && panblock_len == 0) {
					argp_error(state, "PIN block encrypt/decrypt using derivation mode (--mode) AES requires encoded PAN block (--panblock)");
				}
				if (iv) {
					argp_error(state, "Initial vector (--iv) is not allowed for PIN block encrypt/decrypt");
				}
			}

			return 0;

		default:
			return ARGP_ERR_UNKNOWN;
	}
}

// Hex parser helper function
static int parse_hex(const char* hex, void* buf, size_t* buf_len)
{
	size_t max_buf_len;

	if (!buf_len) {
		return -1;
	}
	max_buf_len = *buf_len;
	*buf_len = 0;

	while (*hex && max_buf_len--) {
		uint8_t* ptr = buf;
		char str[3];
		unsigned int str_idx = 0;

		// Find next two valid hex digits
		while (*hex && str_idx < 2) {
			// Skip spaces
			if (isspace(*hex)) {
				++hex;
				continue;
			}
			// Only allow hex digits
			if (!isxdigit(*hex)) {
				return -2;
			}

			str[str_idx++] = *hex;
			++hex;
		}
		str[2] = 0;

		*ptr = strtoul(str, NULL, 16);
		++buf;
		++*buf_len;
	}

	return 0;
}

// File/stdin read helper function
static void* read_file(FILE* file, size_t* len)
{
	const size_t block_size = 4; // Use common page size
	void* buf = NULL;
	size_t buf_len = 0;
	size_t total_len = 0;

	if (!file) {
		*len = 0;
		return NULL;
	}

	do {
		// Grow buffer
		buf_len += block_size;
		buf = realloc(buf, buf_len);

		// Read next block
		total_len += fread(buf + total_len, 1, block_size, file);
		if (ferror(file)) {
			free(buf);
			*len = 0;
			return NULL;
		}
	} while (!feof(file));

	*len = total_len;
	return buf;
}

// Buffer output helper function
static void output_buf(const void* buf, size_t length)
{
	if (output_format == DUKPT_TOOL_OUTPUT_FORMAT_RAW) {
		// Output buffer as raw bytes
		fwrite(buf, length, 1, stdout);
		return;
	}

	// Default to output of buffer as hex digits
	const uint8_t* ptr = buf;
	for (size_t i = 0; i < length; i++) {
		printf("%02X", ptr[i]);
	}
	printf("\n");
}

static int prepare_tdes_ik(bool full_ksn)
{
	int r;

	if (full_ksn) {
		// Validate KSN length
		if (ksn_len != DUKPT_TDES_KSN_LEN) {
			fprintf(stderr, "TDES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2);
			return 1;
		}
	} else {
		// Validate KSN length
		if (ksn_len != DUKPT_TDES_KSN_LEN - 2 &&
			ksn_len != DUKPT_TDES_KSN_LEN
		) {
			fprintf(stderr, "TDES: KSN must be either %u (for IKSN) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_TDES_KSN_LEN - 2, DUKPT_TDES_KSN_LEN,
				(DUKPT_TDES_KSN_LEN - 2) * 2, DUKPT_TDES_KSN_LEN * 2
			);
			return 1;
		}
	}

	// If IK is not available, derive it
	if (!ik) {
		// Validate BDK length
		if (bdk_len != DUKPT_TDES_KEY_LEN) {
			fprintf(stderr, "TDES: BDK must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KEY_LEN, DUKPT_TDES_KEY_LEN * 2);
			return 1;
		}

		ik_len = DUKPT_TDES_KEY_LEN;
		ik = malloc(ik_len);

		// Derive initial key
		r = dukpt_tdes_derive_ik(bdk, ksn, ik);
		if (r) {
			fprintf(stderr, "dukpt_tdes_derive_ik() failed; r=%d\n", r);
			return 1;
		}
	}

	return 0;
}

static int prepare_tdes_txn_key(void)
{
	int r;

	r = prepare_tdes_ik(true);
	if (r) {
		return 1;
	}

	txn_key_len = DUKPT_TDES_KEY_LEN;
	txn_key = malloc(txn_key_len);

	// Derive current transaction key
	r = dukpt_tdes_derive_txn_key(ik, ksn, txn_key);
	if (r) {
		fprintf(stderr, "dukpt_tdes_derive_txn_key() failed; r=%d\n", r);
		return 1;
	}

	return 0;
}

static int do_tdes_mode(void)
{
	int r;

	switch (dukpt_tool_action) {
		case DUKPT_TOOL_ACTION_NONE: {
			fprintf(stderr, "No action specified");
			return 1;
		}

		case DUKPT_TOOL_ACTION_DERIVE_IK:
			r = prepare_tdes_ik(false);
			if (r) {
				return 1;
			}

			output_buf(ik, ik_len);
			return 0;

		case DUKPT_TOOL_ACTION_DERIVE_TXN_KEY:
			r = prepare_tdes_txn_key();
			if (r) {
				return 1;
			}

			output_buf(txn_key, txn_key_len);
			return 0;

		case DUKPT_TOOL_ACTION_ADVANCE_KSN:
			// Validate KSN length
			if (ksn_len != DUKPT_TDES_KSN_LEN) {
				fprintf(stderr, "TDES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_KSN_LEN, DUKPT_TDES_KSN_LEN * 2);
				return 1;
			}

			// Advance to the next transaction
			r = dukpt_tdes_ksn_advance(ksn);
			if (r < 0) {
				fprintf(stderr, "dukpt_tdes_ksn_advance() failed; r=%d\n", r);
				return 1;
			}
			if (r > 0) {
				fprintf(stderr, "KSN exhausted\n");
				return 1;
			}

			output_buf(ksn, ksn_len);
			return 0;

		case DUKPT_TOOL_ACTION_DERIVE_UPDATE_KEY:
			fprintf(stderr, "Update key derivation (--derive-update-key) is only allowed for derivation mode (--mode) AES\n");
			return 1;

		case DUKPT_TOOL_ACTION_ENCRYPT_PINBLOCK: {
			uint8_t encrypted_pinblock[DUKPT_TDES_PINBLOCK_LEN];

			// Validate PIN block length
			if (pinblock_len != DUKPT_TDES_PINBLOCK_LEN) {
				fprintf(stderr, "TDES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_PINBLOCK_LEN, DUKPT_TDES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_tdes_txn_key();
			if (r) {
				return 1;
			}

			// Do it
			r = dukpt_tdes_encrypt_pinblock(txn_key, pinblock, encrypted_pinblock);
			if (r) {
				fprintf(stderr, "dukpt_tdes_encrypt_pinblock() failed; r=%d\n", r);
				return 1;
			}

			output_buf(encrypted_pinblock, sizeof(encrypted_pinblock));
			return 0;
		}

		case DUKPT_TOOL_ACTION_DECRYPT_PINBLOCK: {
			uint8_t decrypted_pinblock[DUKPT_TDES_PINBLOCK_LEN];

			// Validate PIN block length
			if (pinblock_len != DUKPT_TDES_PINBLOCK_LEN) {
				fprintf(stderr, "TDES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_PINBLOCK_LEN, DUKPT_TDES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_tdes_txn_key();
			if (r) {
				return 1;
			}

			// Do it
			r = dukpt_tdes_decrypt_pinblock(txn_key, pinblock, decrypted_pinblock);
			if (r) {
				fprintf(stderr, "dukpt_tdes_decrypt_pinblock() failed; r=%d\n", r);
				return 1;
			}

			output_buf(decrypted_pinblock, sizeof(decrypted_pinblock));
			return 0;
		}

		case DUKPT_TOOL_ACTION_ENCRYPT_REQUEST:
		case DUKPT_TOOL_ACTION_DECRYPT_REQUEST:
		case DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE:
		case DUKPT_TOOL_ACTION_DECRYPT_RESPONSE: {
			uint8_t iv_buf[DUKPT_TDES_BLOCK_LEN];

			// Validate IV length
			if (iv_len && iv_len != DUKPT_TDES_BLOCK_LEN) {
				fprintf(stderr, "TDES: IV length must be %u bytes (thus %u hex digits)\n", DUKPT_TDES_BLOCK_LEN, DUKPT_TDES_BLOCK_LEN * 2);
				return 1;
			}

			// Validate transaction data length
			if ((txn_data_len & (DUKPT_TDES_BLOCK_LEN-1)) != 0) {
				fprintf(stderr, "TDES: Transaction data length must be a multiple of %u bytes\n", DUKPT_TDES_BLOCK_LEN);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_tdes_txn_key();
			if (r) {
				return 1;
			}

			// Prepare IV
			if (iv) {
				memcpy(iv_buf, iv, sizeof(iv_buf));
			} else {
				memset(iv_buf, 0, sizeof(iv_buf));
			}

			// Do it
			switch (dukpt_tool_action) {
				case DUKPT_TOOL_ACTION_ENCRYPT_REQUEST:
					r = dukpt_tdes_encrypt_request(txn_key, iv_buf, txn_data, txn_data_len, txn_data);
					if (r) {
						fprintf(stderr, "dukpt_tdes_encrypt_request() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_DECRYPT_REQUEST:
					r = dukpt_tdes_decrypt_request(txn_key, iv_buf, txn_data, txn_data_len, txn_data);
					if (r) {
						fprintf(stderr, "dukpt_tdes_decrypt_request() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE:
					r = dukpt_tdes_encrypt_response(txn_key, iv_buf, txn_data, txn_data_len, txn_data);
					if (r) {
						fprintf(stderr, "dukpt_tdes_encrypt_response() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_DECRYPT_RESPONSE:
					r = dukpt_tdes_decrypt_response(txn_key, iv_buf, txn_data, txn_data_len, txn_data);
					if (r) {
						fprintf(stderr, "dukpt_tdes_decrypt_response() failed; r=%d\n", r);
						return 1;
					}
					break;

				default:
					// This should never happen
					return -1;
			}

			output_buf(txn_data, txn_data_len);
			return 0;
		}
	}

	// This should never happen
	return -1;
}

static int prepare_aes_ik(bool full_ksn)
{
	int r;

	if (full_ksn) {
		// Validate KSN length
		if (ksn_len != DUKPT_AES_KSN_LEN) {
			fprintf(stderr, "AES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_AES_KSN_LEN, DUKPT_AES_KSN_LEN * 2);
			return 1;
		}
	} else {
		// Validate KSN length
		if (ksn_len != DUKPT_AES_IK_ID_LEN &&
			ksn_len != DUKPT_AES_KSN_LEN
		) {
			fprintf(stderr, "AES: KSN must be either %u (for IK ID) or %u (for full KSN) bytes (thus %u or %u hex digits)\n",
				DUKPT_AES_IK_ID_LEN, DUKPT_AES_KSN_LEN,
				DUKPT_AES_IK_ID_LEN * 2, DUKPT_AES_KSN_LEN * 2
			);
			return 1;
		}
	}

	// If IK is not available, derive it
	if (!ik) {
		// Validate BDK length
		if (bdk_len != DUKPT_AES_KEY_LEN(AES128) &&
			bdk_len != DUKPT_AES_KEY_LEN(AES192) &&
			bdk_len != DUKPT_AES_KEY_LEN(AES256)
		) {
			fprintf(stderr, "AES: BDK must be %u|%u|%u bytes (thus %u|%u|%u hex digits)\n",
				DUKPT_AES_KEY_LEN(AES128), DUKPT_AES_KEY_LEN(AES192), DUKPT_AES_KEY_LEN(AES256),
				DUKPT_AES_KEY_LEN(AES128) * 2, DUKPT_AES_KEY_LEN(AES192) * 2, DUKPT_AES_KEY_LEN(AES256) * 2
			);
			return 1;
		}

		ik_len = bdk_len;
		ik = malloc(ik_len);

		// Derive initial key
		r = dukpt_aes_derive_ik(bdk, bdk_len, ksn, ik);
		if (r) {
			fprintf(stderr, "dukpt_aes_derive_ik() failed; r=%d\n", r);
			return 1;
		}
	}

	return 0;
}

static int prepare_aes_txn_key(void)
{
	int r;

	r = prepare_aes_ik(true);
	if (r) {
		return 1;
	}

	txn_key_len = ik_len;
	txn_key = malloc(txn_key_len);

	// Derive current transaction key
	r = dukpt_aes_derive_txn_key(ik, ik_len, ksn, txn_key);
	if (r) {
		fprintf(stderr, "dukpt_aes_derive_txn_key() failed; r=%d\n", r);
		return 1;
	}

	return 0;
}

static int do_aes_mode(void)
{
	int r;

	// If working key type not specified, default to length of BDK or IK
	if (!key_type_valid) {
		size_t key_len;

		if (bdk) {
			key_len = bdk_len;
		} else if (ik) {
			key_len = ik_len;
		} else {
			key_len = 0;
		}

		switch (key_len) {
			case DUKPT_AES_KEY_LEN(AES128):
				key_type = DUKPT_AES_KEY_TYPE_AES128;
				break;

			case DUKPT_AES_KEY_LEN(AES192):
				key_type = DUKPT_AES_KEY_TYPE_AES192;
				break;

			case DUKPT_AES_KEY_LEN(AES256):
				key_type = DUKPT_AES_KEY_TYPE_AES256;
				break;

			case 0:
				// BDK or IK not available
				break;

			default:
				fprintf(stderr, "Failed to determine working key type\n");
				return 1;
		}
	}

	switch (dukpt_tool_action) {
		case DUKPT_TOOL_ACTION_NONE: {
			fprintf(stderr, "No action specified");
			return 1;
		}

		case DUKPT_TOOL_ACTION_DERIVE_IK:
			r = prepare_aes_ik(false);
			if (r) {
				return 1;
			}

			output_buf(ik, ik_len);
			return 0;

		case DUKPT_TOOL_ACTION_DERIVE_TXN_KEY:
			r = prepare_aes_txn_key();
			if (r) {
				return 1;
			}

			output_buf(txn_key, txn_key_len);
			return 0;

		case DUKPT_TOOL_ACTION_ADVANCE_KSN:
			// Validate KSN length
			if (ksn_len != DUKPT_AES_KSN_LEN) {
				fprintf(stderr, "AES: KSN must be %u bytes (thus %u hex digits)\n", DUKPT_AES_KSN_LEN, DUKPT_AES_KSN_LEN * 2);
				return 1;
			}

			// Advance to the next transaction
			r = dukpt_aes_ksn_advance(ksn);
			if (r < 0) {
				fprintf(stderr, "dukpt_aes_ksn_advance() failed; r=%d\n", r);
				return 1;
			}
			if (r > 0) {
				fprintf(stderr, "KSN exhausted\n");
				return 1;
			}

			output_buf(ksn, ksn_len);
			return 0;

		case DUKPT_TOOL_ACTION_DERIVE_UPDATE_KEY: {
			uint8_t update_key[DUKPT_AES_KEY_LEN(AES256)];
			size_t update_key_len;

			// Determine update key length
			switch (key_type) {
				case DUKPT_AES_KEY_TYPE_AES128:
					update_key_len = DUKPT_AES_KEY_LEN(AES128);
					break;

				case DUKPT_AES_KEY_TYPE_AES192:
					update_key_len = DUKPT_AES_KEY_LEN(AES192);
					break;

				case DUKPT_AES_KEY_TYPE_AES256:
					update_key_len = DUKPT_AES_KEY_LEN(AES256);
					break;

				default:
					fprintf(stderr, "Unsupported key type\n");
					return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_aes_txn_key();
			if (r) {
				return 1;
			}

			// Do it
			r = dukpt_aes_derive_update_key(ik, ik_len, ksn, key_type, update_key);
			if (r) {
				fprintf(stderr, "dukpt_aes_derive_update_key() failed; r=%d\n", r);
				return 1;
			}

			output_buf(update_key, update_key_len);
			return 0;
		}

		case DUKPT_TOOL_ACTION_ENCRYPT_PINBLOCK: {
			uint8_t encrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];

			// Validate PIN block length
			if (pinblock_len != DUKPT_AES_PINBLOCK_LEN) {
				fprintf(stderr, "AES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_AES_PINBLOCK_LEN, DUKPT_AES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Validate PAN block length
			if (panblock_len != DUKPT_AES_PINBLOCK_LEN) {
				fprintf(stderr, "AES: PAN block must be %u bytes (thus %u hex digits)\n", DUKPT_AES_PINBLOCK_LEN, DUKPT_AES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_aes_txn_key();
			if (r) {
				return 1;
			}

			// Do it
			r = dukpt_aes_encrypt_pinblock(
				txn_key,
				txn_key_len,
				ksn,
				key_type,
				pinblock,
				panblock,
				encrypted_pinblock
			);
			if (r) {
				fprintf(stderr, "dukpt_aes_encrypt_pinblock() failed; r=%d\n", r);
				return 1;
			}

			output_buf(encrypted_pinblock, sizeof(encrypted_pinblock));
			return 0;
		}

		case DUKPT_TOOL_ACTION_DECRYPT_PINBLOCK: {
			uint8_t decrypted_pinblock[DUKPT_AES_PINBLOCK_LEN];

			// Validate PIN block length
			if (pinblock_len != DUKPT_AES_PINBLOCK_LEN) {
				fprintf(stderr, "AES: PIN block must be %u bytes (thus %u hex digits)\n", DUKPT_AES_PINBLOCK_LEN, DUKPT_AES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Validate PAN block length
			if (panblock_len != DUKPT_AES_PINBLOCK_LEN) {
				fprintf(stderr, "AES: PAN block must be %u bytes (thus %u hex digits)\n", DUKPT_AES_PINBLOCK_LEN, DUKPT_AES_PINBLOCK_LEN * 2);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_aes_txn_key();
			if (r) {
				return 1;
			}

			// Do it
			r = dukpt_aes_decrypt_pinblock(
				txn_key,
				txn_key_len,
				ksn,
				key_type,
				pinblock,
				panblock,
				decrypted_pinblock
			);
			if (r) {
				fprintf(stderr, "dukpt_aes_decrypt_pinblock() failed; r=%d\n", r);
				return 1;
			}

			output_buf(decrypted_pinblock, sizeof(decrypted_pinblock));
			return 0;
		}

		case DUKPT_TOOL_ACTION_ENCRYPT_REQUEST:
		case DUKPT_TOOL_ACTION_DECRYPT_REQUEST:
		case DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE:
		case DUKPT_TOOL_ACTION_DECRYPT_RESPONSE: {
			uint8_t iv_buf[DUKPT_AES_BLOCK_LEN];

			// Validate IV length
			if (iv_len && iv_len != DUKPT_AES_BLOCK_LEN) {
				fprintf(stderr, "AES: IV length must be %u bytes (thus %u hex digits)\n", DUKPT_AES_BLOCK_LEN, DUKPT_AES_BLOCK_LEN * 2);
				return 1;
			}

			// Validate transaction data length
			if ((txn_data_len & (DUKPT_AES_BLOCK_LEN-1)) != 0) {
				fprintf(stderr, "AES: Transaction data length must be a multiple of %u bytes\n", DUKPT_AES_BLOCK_LEN);
				return 1;
			}

			// Ensure that DUKPT transaction key is available
			r = prepare_aes_txn_key();
			if (r) {
				return 1;
			}

			// Prepare IV
			if (iv) {
				memcpy(iv_buf, iv, sizeof(iv_buf));
			} else {
				memset(iv_buf, 0, sizeof(iv_buf));
			}

			// Do it
			switch (dukpt_tool_action) {
				case DUKPT_TOOL_ACTION_ENCRYPT_REQUEST:
					r = dukpt_aes_encrypt_request(
						txn_key,
						txn_key_len,
						ksn,
						key_type,
						iv_buf,
						txn_data,
						txn_data_len,
						txn_data
					);
					if (r) {
						fprintf(stderr, "dukpt_aes_encrypt_request() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_DECRYPT_REQUEST:
					r = dukpt_aes_decrypt_request(
						txn_key,
						txn_key_len,
						ksn,
						key_type,
						iv_buf,
						txn_data,
						txn_data_len,
						txn_data
					);
					if (r) {
						fprintf(stderr, "dukpt_aes_decrypt_request() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_ENCRYPT_RESPONSE:
					r = dukpt_aes_encrypt_response(
						txn_key,
						txn_key_len,
						ksn,
						key_type,
						iv_buf,
						txn_data,
						txn_data_len,
						txn_data
					);
					if (r) {
						fprintf(stderr, "dukpt_aes_encrypt_response() failed; r=%d\n", r);
						return 1;
					}
					break;

				case DUKPT_TOOL_ACTION_DECRYPT_RESPONSE:
					r = dukpt_aes_decrypt_response(
						txn_key,
						txn_key_len,
						ksn,
						key_type,
						iv_buf,
						txn_data,
						txn_data_len,
						txn_data
					);
					if (r) {
						fprintf(stderr, "dukpt_aes_decrypt_response() failed; r=%d\n", r);
						return 1;
					}
					break;

				default:
					// This should never happen
					return -1;
			}

			output_buf(txn_data, txn_data_len);
			return 0;
		}
	}

	// This should never happen
	return -1;
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
		case DUKPT_TOOL_MODE_TDES:
			r = do_tdes_mode();
			break;

		case DUKPT_TOOL_MODE_AES:
			r = do_aes_mode();
			break;
	}

	// Cleanup
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
	if (pinblock) {
		free(pinblock);
		pinblock = NULL;
		pinblock_len = 0;
	}
	if (panblock) {
		free(panblock);
		panblock = NULL;
		panblock_len = 0;
	}

	if (txn_data) {
		free(txn_data);
		txn_data = NULL;
		txn_data_len = 0;
	}
	if (iv) {
		free(iv);
		iv = NULL;
		iv_len = 0;
	}

	return r;
}
