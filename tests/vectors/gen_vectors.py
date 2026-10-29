#!/usr/bin/env python3
"""Generate the apmon protocol 2 test vectors in docs/PROTOCOL.md (needs python3-cryptography)."""
import hashlib, hmac, json, struct
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def hkdf_extract(salt, ikm): return hmac.new(salt, ikm, hashlib.sha256).digest()
def hkdf_expand(prk, info, n):
    out, t, i = b"", b"", 1
    while len(out) < n:
        t = hmac.new(prk, t + info + bytes([i]), hashlib.sha256).digest(); out += t; i += 1
    return out[:n]

def keys(passphrase, epoch):
    prk = hkdf_extract(b"apmon/2 salt", passphrase.encode())
    e = struct.pack(">I", epoch)
    return prk, hkdf_expand(prk, b"apmon/2 s2c" + e, 32), hkdf_expand(prk, b"apmon/2 c2s" + e, 32)

def header(mtype, flags, epoch, mac, ts_ms, seq, nonce, ct_len):
    return (b"APM2" + bytes([2, mtype]) + struct.pack(">HI", flags, epoch) + mac + b"\0\0"
            + struct.pack(">QI", ts_ms, seq) + nonce + struct.pack(">I", ct_len))

def seal(key, mtype, flags, epoch, mac, ts, seq, nonce, pt):
    h = header(mtype, flags, epoch, mac, ts, seq, nonce, len(pt) + 16)
    return h, h + AESGCM(key).encrypt(nonce, pt, h)

if __name__ == "__main__":
    for pp in ["--__", "correct horse battery staple"]:
        prk, ks, kc = keys(pp, 0)
        print(f"passphrase={pp!r} epoch=0\n PRK={prk.hex()}\n K_s2c={ks.hex()}\n K_c2s={kc.hex()}")
    _, ks, kc = keys("correct horse battery staple", 0)
    mac = bytes.fromhex("9483c4a1b2c3"); nonce = bytes.fromhex("000102030405060708090a0b")
    pt = json.dumps({"v":2,"type":"report","node":{"id":"94:83:c4:a1:b2:c3","hostname":"ap1","uptime":3600},"radios":[],"clients":[]}, separators=(",",":")).encode()
    h, msg = seal(ks, 0x01, 0x0000, 0, mac, 1793270400000, 42, nonce, pt)
    print("REPORT plaintext:", pt.decode()); print(" header:", h.hex()); print(" message:", msg.hex())
    rpt = json.dumps({"v":2,"type":"ack","status":"ok","collector_time":1793270400250,"echo_nonce":nonce.hex(),"interval":30}, separators=(",",":")).encode()
    h2, msg2 = seal(kc, 0x81, 0, 0, bytes.fromhex("9483c4000001"), 1793270400250, 7, bytes.fromhex("0b0a09080706050403020100"), rpt)
    print("ACK plaintext:", rpt.decode()); print(" header:", h2.hex()); print(" message:", msg2.hex())
    # RFC 5869 test case 1 self-check of the HKDF implementation
    p = hkdf_extract(bytes.fromhex("000102030405060708090a0b0c"), bytes.fromhex("0b"*22))
    assert hkdf_expand(p, bytes.fromhex("f0f1f2f3f4f5f6f7f8f9"), 42).hex().startswith("3cb25f25faacd57a90434f64d0362f2a")
    print("RFC 5869 A.1 self-check: OK")
