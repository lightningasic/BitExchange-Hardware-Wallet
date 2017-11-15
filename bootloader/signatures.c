/*
 * This file is part of the TREZOR project.
 *
 * Copyright (C) 2014 Pavol Rusnak <stick@satoshilabs.com>
 *
 * This library is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public License
 * along with this library.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdint.h>

#include "signatures.h"
#include "ecdsa.h"
#include "bootloader.h"

#define PUBKEYS 5

static const uint8_t *pubkey[PUBKEYS] = {
	(uint8_t *)"\x04\x2b\xa0\x5a\x56\xb6\x73\x05\xa7\xb2\xe3\x6c\x9e\xd1\x11\x76\xf7\xab\x32\x28\xf3\xa1\x73\x6b\x1b\x6c\x71\x5d\x0e\x30\xdc\x4e\x22\x1e\x06\x0c\xee\x74\x8f\x4d\x7a\x57\x6d\x17\x63\xc6\x71\x15\xd0\xee\xad\x64\x4f\xe5\xbf\xae\x74\x52\x61\xdf\xaf\x55\x60\x05\x52",
	(uint8_t *)"\x04\xd5\x9c\x39\xd7\x4c\xf4\xc8\xf1\x05\xab\xfc\x61\xba\x4a\xc9\xe2\x27\x0f\x61\x05\x81\x69\x29\x2f\xd5\x36\x04\x46\x11\xaa\xd7\x29\x17\x47\xa3\xfd\xd6\xfc\x9c\x74\xe5\xe6\xbf\x24\x31\x0f\xc6\xa2\x64\xaa\x5b\xcd\x35\xfc\x0f\xff\x57\x01\xef\x1c\x08\x39\x2c\x52",
	(uint8_t *)"\x04\xa8\xbb\x22\xe1\x63\x7f\x56\xba\x79\x06\xc6\x85\xa9\x3b\x44\x76\xe2\xd6\x49\xd2\xb2\x57\x82\x93\xdd\xda\xd5\x8f\x23\x88\x46\xda\xda\xc2\x99\x2e\xee\x49\x06\xb7\xae\x4e\xeb\x63\x59\x5c\xed\x39\x65\x28\x7c\x30\x8f\x7d\x7e\x69\x1e\x9a\xbb\x4d\x32\x1b\xff\x34",
	(uint8_t *)"\x04\x0b\xaa\xa9\x52\x38\x01\xe2\x9c\x68\x45\xb1\x7f\xf4\xe2\x2d\x2e\x29\x9a\x65\xc5\xd0\xd6\xc2\xb9\x15\x22\x22\x2b\x8a\xf4\x7b\xcc\xbe\xb2\xd3\xf6\x41\x1c\x27\xad\xc2\xdd\xa6\x2a\x72\xd5\xba\x0a\x6b\xc0\x4c\x84\x7b\x20\x5c\x95\x71\xe2\xcf\x2f\x2d\x39\x1a\xf6",
	(uint8_t *)"\x04\x6e\x0e\x14\xed\x62\x19\xff\x34\xa7\x2c\x4d\x58\xe0\x34\x01\xee\xa4\x11\xab\x68\x17\x5e\x5b\x9b\x65\x0e\x51\x60\x7b\x49\xbf\x11\x1b\xd5\x30\xb4\x51\x80\xb8\x0f\xac\x98\x98\x8d\x05\x18\xea\x16\x9e\x9d\x65\xfe\xf2\x77\x2b\x38\x8f\x23\x09\xc3\xd1\x5c\xbe\xea",
};

#define SIGNATURES 3

int signatures_ok(void)
{
	uint32_t codelen = *((uint32_t *)FLASH_META_CODELEN);
	uint8_t sigindex1, sigindex2, sigindex3;

	sigindex1 = *((uint8_t *)FLASH_META_SIGINDEX1);
	sigindex2 = *((uint8_t *)FLASH_META_SIGINDEX2);
	sigindex3 = *((uint8_t *)FLASH_META_SIGINDEX3);

	if (sigindex1 < 1 || sigindex1 > PUBKEYS) return 0; // invalid index
	if (sigindex2 < 1 || sigindex2 > PUBKEYS) return 0; // invalid index
	if (sigindex3 < 1 || sigindex3 > PUBKEYS) return 0; // invalid index

	if (sigindex1 == sigindex2) return 0; // duplicate use
	if (sigindex1 == sigindex3) return 0; // duplicate use
	if (sigindex2 == sigindex3) return 0; // duplicate use

	if (ecdsa_verify(pubkey[sigindex1 - 1], (uint8_t *)FLASH_META_SIG1, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
		return 0;
	}
	if (ecdsa_verify(pubkey[sigindex2 - 1], (uint8_t *)FLASH_META_SIG2, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
		return 0;
	}
	if (ecdsa_verify(pubkey[sigindex3 - 1], (uint8_t *)FLASH_META_SIG3, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failture
		return 0;
	}

	return 1;
}
