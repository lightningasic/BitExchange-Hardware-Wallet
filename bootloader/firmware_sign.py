#!/usr/bin/python
import argparse
import hashlib
import struct
import binascii
import ecdsa

SLOTS = 3

pubkeys = {
    1: '0495df26eb818f4b8979053b08aaa719fe6afcccbf83d226bfc94511e6bb56dc24ccee67dc8a5fbca5fd3dc23fb5a7329b6960605f10918877c9f6b2819c28e3cc',
    2: '04b79e2825341029f7ed0d9b4e6259f957d9e15e16e3233691e4bfa4b74171f357b0ca2ee31403cc43495a5e462cdcb56175361e035435c7d01139c832dc4da820',
    3: '0407db41eecbcfdf55377a0075b24c0a26405eb8824b0d2c08807bd3122989535a73660bb0fba36b3de466f57ff9ecf3674561ca211339640c24b6524b9c5a2507',
    4: '04b8fc03499db230d230508982d308e221946c0deb07c96387be127f553ffcaaa198e7468db37a9493b0b3367df2d275447a5583ab5ab4c11fdfc0239be7e705b0',
    5: '044fbf683136879ee71651b5c5e860e89411974104711c10584891b2da3da03a1c43ff42af780103d08337dc34147686f4a026dc8dad6029da9ccb87e28e872de0',
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
