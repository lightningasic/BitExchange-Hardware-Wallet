APPVER = 1.1.0

NAME  = bitexchange

OBJS += usb.o
OBJS += messages.o
OBJS += storage.o
OBJS += bitexchange.o
OBJS += pinmatrix.o
OBJS += fsm.o
OBJS += coins.o
OBJS += transaction.o
OBJS += protect.o
OBJS += layout2.o
OBJS += recovery.o
OBJS += reset.o
OBJS += signing.o
OBJS += crypto.o

OBJS += debug.o

OBJS += ../bitexchange-crypto/address.o
OBJS += ../bitexchange-crypto/bignum.o
OBJS += ../bitexchange-crypto/ecdsa.o
OBJS += ../bitexchange-crypto/curves.o
OBJS += ../bitexchange-crypto/secp256k1.o
OBJS += ../bitexchange-crypto/nist256p1.o

OBJS += ../bitexchange-crypto/ed25519-donna/curve25519-donna-32bit.o
OBJS += ../bitexchange-crypto/ed25519-donna/curve25519-donna-helpers.o
OBJS += ../bitexchange-crypto/ed25519-donna/modm-donna-32bit.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519-donna-basepoint-table.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519-donna-32bit-tables.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519-donna-impl-base.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519.o
OBJS += ../bitexchange-crypto/ed25519-donna/curve25519-donna-scalarmult-base.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519-sha3.o
OBJS += ../bitexchange-crypto/ed25519-donna/ed25519-keccak.o

OBJS += ../bitexchange-crypto/hmac.o
OBJS += ../bitexchange-crypto/bip32.o
OBJS += ../bitexchange-crypto/bip39.o
OBJS += ../bitexchange-crypto/pbkdf2.o
OBJS += ../bitexchange-crypto/base32.o
OBJS += ../bitexchange-crypto/base58.o

OBJS += ../bitexchange-crypto/ripemd160.o
OBJS += ../bitexchange-crypto/sha2.o
OBJS += ../bitexchange-crypto/sha3.o

OBJS += ../bitexchange-crypto/aes/aescrypt.o
OBJS += ../bitexchange-crypto/aes/aeskey.o
OBJS += ../bitexchange-crypto/aes/aestab.o
OBJS += ../bitexchange-crypto/aes/aes_modes.o

OBJS += ../bitexchange-crypto/nem.o

OBJS += ../bitexchange-qrenc/qr_encode.o

#OBJS += protob/pb_common.o
OBJS += protob/pb_decode.o
OBJS += protob/pb_encode.o
OBJS += protob/messages.pb.o
OBJS += protob/storage.pb.o
OBJS += protob/types.pb.o

include ../Makefile.include

CFLAGS += -Wno-sequence-point
CFLAGS += -Iprotob -DPB_FIELD_16BIT=1
CFLAGS += -DQR_MAX_VERSION=0
CFLAGS += -DDEBUG_LINK=0
CFLAGS += -DDEBUG_LOG=0
#CFLAGS += -DSCM_REVISION='"$(shell git rev-parse HEAD | sed 's:\(..\):\\x\1:g')"'
