import secrets
import hmac
import hashlib
import os
import struct
import subprocess

gpshell_template = """
 mode_211
 enable_trace
 establish_context
 card_connect
 select -AID A000000151000000
 open_sc -security 1 -keyind 0 -keyver 0 -mac_key 404142434445464748494a4b4c4d4e4f -enc_key 404142434445464748494a4b4c4d4e4f -kek_key 404142434445464748494a4b4c4d4e4f
 send_apdu_nostop -sc 1 -APDU 80E400800E4F0C53746174757357616C6C6574
 install_for_load -pkgAID 53746174757357616C6C6574
 load -file wallet.cap
 send_apdu -sc 1 -APDU 80E60C005F0C53746174757357616C6C65740F53746174757357616C6C65744170700F53746174757357616C6C657441707001002EC92C{:s}{:s}00
 card_disconnect
 release_context
"""

def pbkdf2(digestmod, password: 'bytes', salt, count, dk_length) -> 'bytes':
    def pbkdf2_function(pw, salt, count, i):
        # in the first iteration, the hmac message is the salt
        # concatinated with the block number in the form of \x00\x00\x00\x01
        r = u = hmac.new(pw, salt + struct.pack(">i", i), digestmod).digest()
        for i in range(2, count + 1):
            # in subsequent iterations, the hmac message is the
            # previous hmac digest. The key is always the users password
            # see the hmac specification for notes on padding and stretching
            u = hmac.new(pw, u, digestmod).digest()
            # this is the exclusive or of the two byte-strings
            r = bytes(i ^ j for i, j in zip(r, u))
        return r
    dk, h_length = b'', digestmod().digest_size
    # we generate as many blocks as are required to
    # concatinate to the desired key size:
    blocks = (dk_length // h_length) + (1 if dk_length % h_length else 0)
    for i in range(1, blocks + 1):
        dk += pbkdf2_function(password, salt, count, i)
    # The length of the key wil be dk_length to the nearest
    # hash block size, i.e. larger than or equal to it. We
    # slice it to the desired length befor returning it.
    return dk[:dk_length]
	
def run():
	puk = '{:012d}'.format(secrets.randbelow(999999999999))
	pairing = secrets.token_urlsafe(12)
	pairing_key = pbkdf2(hashlib.sha256, pairing.encode('utf-8'), 'Status Hardware Wallet Lite'.encode('utf-8'), 50000, 32).hex()
	perso_script = gpshell_template.format(puk.encode('utf-8').hex(), pairing_key)
	subprocess.run("gpshell", shell=True, check=True, input=perso_script.encode('utf-8'))
	
	print('\n**************************************\nPairing password: {:s}\nPUK: {:s}'.format(pairing, puk))
if __name__ == '__main__':
    run()