import os
import io
from contextlib import redirect_stdout
import secp256k1
import unittest
from random import randint
import json
from test_util import run_circom, clean, TC
import sys

# Local imports
sys.path.insert(1, '../../src/python_util')
import poseidon_hash


MAX_VAL = 0x30644e72e131a029b85045b68181585d2833e84879b9709143e1f593f0000001
WIDTH = 16
N_ROUNDS_P = [56, 57, 56, 60, 60, 63, 64, 63, 60, 66, 60, 65, 70, 60, 64, 68]
PRIME = 0xfffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f


class TestEcdsaSecp256k1(unittest.TestCase):

    def test_tree8(self):
        circuit_name = "ver"
        n = 8

        cs, out_bytes = prep(n)

        privkey = secp256k1.PrivateKey()
        pubkey = privkey.pubkey

        sig = privkey.ecdsa_sign(out_bytes, raw=True)
        verified = pubkey.ecdsa_verify(out_bytes, sig, raw=True)
        assert verified

        r, s = get_rs(sig)
        pubkey_bytes = pubkey.serialize(False)
        Qx_bytes = pubkey_bytes[1:33]
        Qy_bytes = pubkey_bytes[33:]
        Qx = int.from_bytes(Qx_bytes, "big")
        Qy = int.from_bytes(Qy_bytes, "big")

        inpt = {"r": str(r), "s": str(s), "hashed_claims": [str(c) for c in cs], "Qx": str(Qx), "Qy": str(Qy)}
        inpt_json = json.dumps(inpt)
        inpt_path = os.path.join(TC, "input.json")
        with open(inpt_path, "w") as inpt_file:
            inpt_file.write(inpt_json)

        circ = gen_circ(n)
        with open(os.path.join(TC, f"{circuit_name}.circom"), "w") as f:
            f.write(circ)

        circuit_compilation, wg_compilation, witness_generation = run_circom(circuit_name)
        clean(circuit_name)

        assert circuit_compilation
        assert wg_compilation
        assert witness_generation

    def test_tree16(self):
        circuit_name = "ver"
        n = 16

        cs, out_bytes = prep(n)

        privkey = secp256k1.PrivateKey()
        pubkey = privkey.pubkey

        sig = privkey.ecdsa_sign(out_bytes, raw=True)
        verified = pubkey.ecdsa_verify(out_bytes, sig, raw=True)
        assert verified

        r, s = get_rs(sig)
        pubkey_bytes = pubkey.serialize(False)
        Qx_bytes = pubkey_bytes[1:33]
        Qy_bytes = pubkey_bytes[33:]
        Qx = int.from_bytes(Qx_bytes, "big")
        Qy = int.from_bytes(Qy_bytes, "big")

        inpt = {"r": str(r), "s": str(s), "hashed_claims": [str(c) for c in cs], "Qx": str(Qx), "Qy": str(Qy)}
        inpt_json = json.dumps(inpt)
        inpt_path = os.path.join(TC, "input.json")
        with open(inpt_path, "w") as inpt_file:
            inpt_file.write(inpt_json)

        circ = gen_circ(n)
        with open(os.path.join(TC, f"{circuit_name}.circom"), "w") as f:
            f.write(circ)

        circuit_compilation, wg_compilation, witness_generation = run_circom(circuit_name)
        clean(circuit_name)

        assert circuit_compilation
        assert wg_compilation
        assert witness_generation

    def test_tree250(self):
        circuit_name = "ver"
        n = 250

        cs, out_bytes = prep(n)

        privkey = secp256k1.PrivateKey()
        pubkey = privkey.pubkey

        sig = privkey.ecdsa_sign(out_bytes, raw=True)
        verified = pubkey.ecdsa_verify(out_bytes, sig, raw=True)
        assert verified

        r, s = get_rs(sig)
        pubkey_bytes = pubkey.serialize(False)
        Qx_bytes = pubkey_bytes[1:33]
        Qy_bytes = pubkey_bytes[33:]
        Qx = int.from_bytes(Qx_bytes, "big")
        Qy = int.from_bytes(Qy_bytes, "big")

        inpt = {"r": str(r), "s": str(s), "hashed_claims": [str(c) for c in cs], "Qx": str(Qx), "Qy": str(Qy)}
        inpt_json = json.dumps(inpt)
        inpt_path = os.path.join(TC, "input.json")
        with open(inpt_path, "w") as inpt_file:
            inpt_file.write(inpt_json)

        circ = gen_circ(n)
        with open(os.path.join(TC, f"{circuit_name}.circom"), "w") as f:
            f.write(circ)

        circuit_compilation, wg_compilation, witness_generation = run_circom(circuit_name)
        clean(circuit_name)

        assert circuit_compilation
        assert wg_compilation
        assert witness_generation

def prep(n):
    output_capture = io.StringIO()
    with redirect_stdout(output_capture):
        security_level = 128
        alpha = 5

        cs = [randint(0, MAX_VAL) for _ in range(n)]

        l2 = n // WIDTH
        rm = n % WIDTH

        bl = [0 for _ in range(l2)]

        tl_out = 0

        if n > 16:
            for i in range(l2):
                t = WIDTH + 1
                tmp = cs[WIDTH * i:WIDTH * (i + 1)]

                pout = poseidon_hash.hash(tmp)
                bl[i] = int(pout)

            if rm > 0:
                tmp = cs[WIDTH * l2:]
                t = len(tmp) + 1

                pout = poseidon_hash.hash(tmp)
                bl.append(int(pout))

            t = len(bl) + 1

            tl_out = poseidon_hash.hash(bl)
            out_bytes = (int(tl_out)).to_bytes(32, 'big')

        else:
            t = n + 1
            tmp = cs[:]

            tl_out = poseidon_hash.hash(tmp)
            out_bytes = (int(tl_out)).to_bytes(32, 'big')

        return cs, out_bytes

def gen_circ(n):
    s = "pragma circom 2.1.2;\n"
    s += "include \"../../cred_ver.circom\";\n"
    s += "template Ver() {\n"
    s += "signal input Qx;\n"
    s += "signal input Qy;\n"
    s += f"signal input hashed_claims[{n}];\n"
    s += "signal input r;\n"
    s += "signal input s;\n"
    s += f"component vc = VerifyCredential({n});\n"
    s += "vc.Qx <== Qx;\n"
    s += "vc.Qy <== Qy;\n"
    s += "vc.hashed_claims <== hashed_claims;\n"
    s += "vc.r <== r;\n"
    s += "vc.s <== s;\n"
    s += "vc.valid === 1;\n}\n"
    s += "component main = Ver();"

    return s

def get_rs(sig):
    ecdsa = secp256k1.ECDSA()
    sig_der = ecdsa.ecdsa_serialize(sig)

    hdr = sig_der[0]
    assert hdr == 0x30

    len_data = sig_der[1]

    x02 = sig_der[2]
    assert x02 == 0x02

    len_r = sig_der[3]
    r = sig_der[4:len_r + 4]

    x02 = sig_der[len_r + 4]
    assert x02 == 0x02

    len_s = sig_der[len_r + 5]
    s = sig_der[len_r + 6:len_r + len_s + 6]

    return int.from_bytes(r, "big"), int.from_bytes(s, "big")

if __name__ == "__main__":
    unittest.main()
