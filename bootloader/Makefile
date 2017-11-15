NAME  = bootloader

MCU_DIR=$(subst /bootloader,,$(PWD))

OBJS += bootloader.o
OBJS += signatures.o
OBJS += usb.o

OBJS += $(MCU_DIR)/bitexchange-crypto/bignum.small.o
OBJS += $(MCU_DIR)/bitexchange-crypto/ecdsa.small.o
OBJS += $(MCU_DIR)/bitexchange-crypto/hmac.o
OBJS += $(MCU_DIR)/bitexchange-crypto/ripemd160.o
OBJS += $(MCU_DIR)/bitexchange-crypto/secp256k1.small.o
OBJS += $(MCU_DIR)/bitexchange-crypto/sha2.o

CFLAGS += -DUSE_PRECOMPUTED_IV=0
CFLAGS += -DUSE_PRECOMPUTED_CP=0

include $(MCU_DIR)/Makefile.include

align:
	./firmware_align.py $(NAME).bin
