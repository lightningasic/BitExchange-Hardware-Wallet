#!/usr/bin/python
import argparse
import hashlib
import struct
import binascii
import ecdsa

SLOTS = 3

pubkeys = {
    1: '042ba05a56b67305a7b2e36c9ed11176f7ab3228f3a1736b1b6c715d0e30dc4e221e060cee748f4d7a576d1763c67115d0eead644fe5bfae745261dfaf55600552',
    2: '04d59c39d74cf4c8f105abfc61ba4ac9e2270f61058169292fd536044611aad7291747a3fdd6fc9c74e5e6bf24310fc6a264aa5bcd35fc0fff5701ef1c08392c52',
    3: '04a8bb22e1637f56ba7906c685a93b4476e2d649d2b2578293dddad58f238846dadac2992eee4906b7ae4eeb63595ced3965287c308f7d7e691e9abb4d321bff34',
    4: '040baaa9523801e29c6845b17ff4e22d2e299a65c5d0d6c2b91522222b8af47bccbeb2d3f6411c27adc2dda62a72d5ba0a6bc04c847b205c9571e2cf2f2d391af6',
    5: '046e0e14ed6219ff34a72c4d58e03401eea411ab68175e5b9b650e51607b49bf111bd530b45180b80fac98988d0518ea169e9d65fef2772b388f2309c3d15cbeea',
}

INDEXES_START = len('BIEX') + struct.calcsize('<I')
SIG_START = INDEXES_START + SLOTS + 1 + 52

def parse_args():
    parser = argparse.ArgumentParser(description='Commandline tool for signing Trezor firmware.')
    parser.add_argument('-f', '--file', dest='path', help="Firmware file to modify")
    parser.add_argument('-s', '--sign', dest='sign', action='store_true', help="Add signature to firmware slot")
    parser.add_argument('-p', '--pem', dest='pem', action='store_true', help="Use PEM instead of SECEXP")
    parser.add_argument('-g', '--generate', dest='generate', action='store_true', help='Generate new ECDSA keypair')

    return parser.parse_args()

def prepare(data):
    # Takes raw OR signed firmware and clean out metadata structure
    # This produces 'clean' data for signing

    meta = 'BIEX'  # magic
    if data[:4] == 'BIEX':
        meta += data[4:4 + struct.calcsize('<I')]
    else:
        meta += struct.pack('<I', len(data))  # length of the code
    meta += '\x00' * SLOTS  # signature index #1-#3
    meta += '\x01'       # flags
    meta += '\x00' * 52  # reserved
    meta += '\x00' * 64 * SLOTS  # signature #1-#3
#    print "meta : ", meta

    if data[:4] == 'BIEX':
        # Replace existing header
        out = meta + data[len(meta):]
    else:
        # create data from meta + code
        out = meta + data

    return out

def check_signatures(data):
    # Analyses given firmware and prints out
    # status of included signatures

    indexes = [ ord(x) for x in data[INDEXES_START:INDEXES_START + SLOTS] ]

    to_sign = prepare(data)[256:] # without meta
    fingerprint = hashlib.sha256(to_sign).hexdigest()

    print "Firmware fingerprint:", fingerprint

    used = []
    for x in range(SLOTS):
        signature = data[SIG_START + 64 * x:SIG_START + 64 * x + 64]

        if indexes[x] == 0:
            print "Slot #%d" % (x + 1), 'is empty'
        else:
            pk = pubkeys[indexes[x]]
            verify = ecdsa.VerifyingKey.from_string(binascii.unhexlify(pk)[1:],
                        curve=ecdsa.curves.SECP256k1, hashfunc=hashlib.sha256)

            try:
                verify.verify(signature, to_sign, hashfunc=hashlib.sha256)

                if indexes[x] in used:
                    print "Slot #%d signature: DUPLICATE" % (x + 1), binascii.hexlify(signature)
                else:
                    used.append(indexes[x])
                    print "Slot #%d signature: VALID" % (x + 1), binascii.hexlify(signature)

            except:
                print "Slot #%d signature: INVALID" % (x + 1), binascii.hexlify(signature)


def modify(data, slot, index, signature):
    # Replace signature in data

    # Put index to data
    data = data[:INDEXES_START + slot - 1 ] + chr(index) + data[INDEXES_START + slot:]

    # Put signature to data
    data = data[:SIG_START + 64 * (slot - 1) ] + signature + data[SIG_START + 64 * slot:]

    return data

def sign(data, is_pem):
    # Ask for index and private key and signs the firmware

    slot = int(raw_input('Enter signature slot (1-%d): ' % SLOTS))
    if slot < 1 or slot > SLOTS:
        raise Exception("Invalid slot")

    if is_pem:
        print "Paste ECDSA private key in PEM format and press Enter:"
        print "(blank private key removes the signature on given index)"
        pem_key = ''
        while True:
            key = raw_input()
            pem_key += key + "\n"
            if key == '':
                break
        if pem_key.strip() == '':
            # Blank key,let's remove existing signature from slot
            return modify(data, slot, 0, '\x00' * 64)
        key = ecdsa.SigningKey.from_pem(pem_key)
    else:
        print "Paste SECEXP (in hex) and press Enter:"
        print "(blank private key removes the signature on given index)"
        secexp = raw_input()
        if secexp.strip() == '':
            # Blank key,let's remove existing signature from slot
            return modify(data, slot, 0, '\x00' * 64)
        key = ecdsa.SigningKey.from_secret_exponent(secexp = int(secexp, 16), curve=ecdsa.curves.SECP256k1, hashfunc=hashlib.sha256)
        print "key:"
        print key

    to_sign = prepare(data)[256:] # without meta

    # Locate proper index of current signing key
    pubkey = '04' + binascii.hexlify(key.get_verifying_key().to_string())
    index = None
    for i, pk in pubkeys.iteritems():
        if pk == pubkey:
            index = i
            break

    if index == None:
        raise Exception("Unable to find private key index. Unknown private key?")

    signature = key.sign_deterministic(to_sign, hashfunc=hashlib.sha256)

    print "signature:"
    print binascii.hexlify(signature)

    return modify(data, slot, index, signature)

def main(args):
    if args.generate:
        key = ecdsa.SigningKey.generate(
            curve=ecdsa.curves.SECP256k1,
            hashfunc=hashlib.sha256)

        print "PRIVATE KEY (SECEXP):"
        print binascii.hexlify(key.to_string())
        print

        print "PRIVATE KEY (PEM):"
        print key.to_pem()

        print "PUBLIC KEY:"
        print '04' + binascii.hexlify(key.get_verifying_key().to_string())
        return

    if not args.path:
        raise Exception("-f/--file is required")

    data = open(args.path, 'rb').read()
    assert len(data) % 4 == 0

    if data[:4] != 'BIEX':
        print "Metadata has been added..."
        data = prepare(data)

    if data[:4] != 'BIEX':
        raise Exception("Firmware header expected")

    print "Firmware size %d bytes" % len(data)

    check_signatures(data)

    if args.sign:
        data = sign(data, args.pem)
        check_signatures(data)

    fp = open(args.path, 'w')
    fp.write(data)
    fp.close()

if __name__ == '__main__':
    args = parse_args()
    main(args)
