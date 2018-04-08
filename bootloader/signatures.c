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
#include "secp256k1.h"
#include "bootloader.h"

#define PUBKEYS 5

static const uint8_t *pubkey[PUBKEYS] = {
    (uint8_t *)"\x04\x95\xdf\x26\xeb\x81\x8f\x4b\x89\x79\x05\x3b\x08\xaa\xa7\x19\xfe\x6a\xfc\xcc\xbf\x83\xd2\x26\xbf\xc9\x45\x11\xe6\xbb\x56\xdc\x24\xcc\xee\x67\xdc\x8a\x5f\xbc\xa5\xfd\x3d\xc2\x3f\xb5\xa7\x32\x9b\x69\x60\x60\x5f\x10\x91\x88\x77\xc9\xf6\xb2\x81\x9c\x28\xe3\xcc",
    (uint8_t *)"\x04\xb7\x9e\x28\x25\x34\x10\x29\xf7\xed\x0d\x9b\x4e\x62\x59\xf9\x57\xd9\xe1\x5e\x16\xe3\x23\x36\x91\xe4\xbf\xa4\xb7\x41\x71\xf3\x57\xb0\xca\x2e\xe3\x14\x03\xcc\x43\x49\x5a\x5e\x46\x2c\xdc\xb5\x61\x75\x36\x1e\x03\x54\x35\xc7\xd0\x11\x39\xc8\x32\xdc\x4d\xa8\x20",
    (uint8_t *)"\x04\x07\xdb\x41\xee\xcb\xcf\xdf\x55\x37\x7a\x00\x75\xb2\x4c\x0a\x26\x40\x5e\xb8\x82\x4b\x0d\x2c\x08\x80\x7b\xd3\x12\x29\x89\x53\x5a\x73\x66\x0b\xb0\xfb\xa3\x6b\x3d\xe4\x66\xf5\x7f\xf9\xec\xf3\x67\x45\x61\xca\x21\x13\x39\x64\x0c\x24\xb6\x52\x4b\x9c\x5a\x25\x07",
    (uint8_t *)"\x04\xb8\xfc\x03\x49\x9d\xb2\x30\xd2\x30\x50\x89\x82\xd3\x08\xe2\x21\x94\x6c\x0d\xeb\x07\xc9\x63\x87\xbe\x12\x7f\x55\x3f\xfc\xaa\xa1\x98\xe7\x46\x8d\xb3\x7a\x94\x93\xb0\xb3\x36\x7d\xf2\xd2\x75\x44\x7a\x55\x83\xab\x5a\xb4\xc1\x1f\xdf\xc0\x23\x9b\xe7\xe7\x05\xb0",
    (uint8_t *)"\x04\x4f\xbf\x68\x31\x36\x87\x9e\xe7\x16\x51\xb5\xc5\xe8\x60\xe8\x94\x11\x97\x41\x04\x71\x1c\x10\x58\x48\x91\xb2\xda\x3d\xa0\x3a\x1c\x43\xff\x42\xaf\x78\x01\x03\xd0\x83\x37\xdc\x34\x14\x76\x86\xf4\xa0\x26\xdc\x8d\xad\x60\x29\xda\x9c\xcb\x87\xe2\x8e\x87\x2d\xe0",
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

	if (ecdsa_verify(&secp256k1, pubkey[sigindex1 - 1], (uint8_t *)FLASH_META_SIG1, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
		return 0;
	}
	if (ecdsa_verify(&secp256k1, pubkey[sigindex2 - 1], (uint8_t *)FLASH_META_SIG2, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failure
		return 0;
	}
	if (ecdsa_verify(&secp256k1, pubkey[sigindex3 - 1], (uint8_t *)FLASH_META_SIG3, (uint8_t *)FLASH_APP_START, codelen) != 0) { // failture
		return 0;
	}

	return 1;
}
