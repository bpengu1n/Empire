import os
import struct
import binascii
import base64

LANGUAGE = {
    'NONE' : 0,
    'POWERSHELL' : 1,
    'PYTHON' : 2
}

LANGUAGE_IDS = {}
for name, ID in LANGUAGE.items(): LANGUAGE_IDS[ID] = name

META = {
    'NONE' : 0,
    'STAGING_REQUEST' : 1,
    'STAGING_RESPONSE' : 2,
    'TASKING_REQUEST' : 3,
    'RESULT_POST' : 4,
    'SERVER_RESPONSE' : 5
}
META_IDS = {}
for name, ID in META.items(): META_IDS[ID] = name

ADDITIONAL = {}
ADDITIONAL_IDS = {}
for name, ID in ADDITIONAL.items(): ADDITIONAL_IDS[ID] = name


def rc4_init(key):
    """RC4 Key Scheduling Algorithm (KSA)"""
    global p, q, state
    state = [n for n in range(256)]
    p = q = j = 0
    for i in range(256):
        if len(key) > 0:
            j = (j + state[i] + ord(key[i % len(key)])) % 256
        else:
            j = (j + state[i]) % 256
        state[i], state[j] = state[j], state[i]
def byteGenerator():
    """RC4 Pseudo-Random Generation Algorithm (PRGA)"""
    global p, q, state
    p = (p + 1) % 256
    q = (q + state[p]) % 256
    state[p], state[q] = state[q], state[p]
    return state[(state[p] + state[q]) % 256]
def rc4_enc(key, inputString):
    """Encrypt input string returning a byte list"""
    rc4_init(key)
    return bytearray([ord(p) ^ byteGenerator() for p in inputString])
def rc4_dec(key, inputByteList):
    """Decrypt input byte list returning a string"""
    print(key, inputByteList)
    rc4_init(key)
    p = "".join([chr(c ^ byteGenerator()) for c in bytearray(inputByteList)])
    print(p)
    return p

def parse_routing_packet(stagingKey, data):
    """
    Decodes the rc4 "routing packet" and parses raw agent data into:

        {sessionID : (language, meta, additional, [encData]), ...}

    Routing packet format:

        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+

        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """

    if data:
        results = {}
        offset = 0
        data = base64.b64decode(data)

        # ensure we have at least the 20 bytes for a routing packet
        if len(data) >= 20:

            while True:

                if len(data) - offset < 20:
                    break

                RC4IV = data[0+offset:4+offset]
                RC4data = data[4+offset:20+offset]
                routingPacket = rc4_dec(RC4IV+stagingKey, RC4data)
                print("InPacket: {}".format(binascii.hexlify(routingPacket)))
                sessionID = routingPacket[0:8]

                # B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
                (language, meta, additional, length) = struct.unpack("=BBHL", routingPacket[8:])

                if length < 0:
                    encData = None
                else:
                    encData = data[(20+offset):(20+offset+length)]

                results[sessionID] = (LANGUAGE_IDS.get(language, 'NONE'), META_IDS.get(meta, 'NONE'), ADDITIONAL_IDS.get(additional, 'NONE'), encData)

                # check if we're at the end of the packet processing
                remainingData = data[20+offset+length:]
                if not remainingData or remainingData == '':
                    break

                offset += 20 + length

            return results

        else:
            print "[*] parse_agent_data() data length incorrect: %s" % (len(data))
            return None

    else:
        print "[*] parse_agent_data() data is None"
        return None


def build_routing_packet(stagingKey, sessionID, meta=0, additional=0, encData=''):
    """
    Takes the specified parameters for an RC4 "routing packet" and builds/returns
    an HMAC'ed RC4 "routing packet".

    packet format:

        Routing Packet:
        +---------+-------------------+--------------------------+
        | RC4 IV  | RC4s(RoutingData) | AESc(client packet data) | ...
        +---------+-------------------+--------------------------+
        |    4    |         16        |        RC4 length        |
        +---------+-------------------+--------------------------+

        RC4s(RoutingData):
        +-----------+------+------+-------+--------+
        | SessionID | Lang | Meta | Extra | Length |
        +-----------+------+------+-------+--------+
        |    8      |  1   |  1   |   2   |    4   |
        +-----------+------+------+-------+--------+

    """

    # binary pack all of the passed config values as unsigned numbers
    #   B == 1 byte unsigned char, H == 2 byte unsigned short, L == 4 byte unsigned long
    data = sessionID + struct.pack("=BBHL", 2, meta, additional, len(encData))

    RC4IV = binascii.hexlify(os.urandom(2))
    key = RC4IV + stagingKey[:28]
    rc4EncData = rc4_enc(key, data)
    packet = RC4IV + rc4EncData + encData
    return packet
