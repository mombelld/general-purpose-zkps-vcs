import secp256k1
from ecdsa.curves import SECP256k1 as curve_s256k1
from ecdsa.ellipticcurve import Point
import unittest
import json
import os

from test_util import run_circom, clean, TC

class TestEcdsaSecp256k1(unittest.TestCase):

    def test_eff_ecdsa(self):
        circuit_name = "eff_ecdsa_test"
        m = 0x1a3614c3fc1ed79b2f3ba2864f632ebed77ef241e3774d6421dfd11539c51943
        m_bytes = m.to_bytes(32, 'big')

        privkey = secp256k1.PrivateKey()
        pubkey = privkey.pubkey

        sig = privkey.ecdsa_sign(m_bytes)
        verified = pubkey.ecdsa_verify(m_bytes, sig)
        assert verified

        r, s = get_rs(sig)

        pubkey_bytes = pubkey.serialize(False)
        Qx_bytes = pubkey_bytes[1:33]
        Qy_bytes = pubkey_bytes[33:]
        Qx = int.from_bytes(Qx_bytes, "big")
        Qy = int.from_bytes(Qy_bytes, "big")

        Tx, Ty, Ux, Uy = getTU(r, s, m, Qx, Qy)

        inpt = {"s": str(s), "Tx": str(Tx), "Ty": str(Ty), "Ux": str(Ux), "Uy": str(Uy), "Qx": str(Qx), "Qy": str(Qy)}

        inpt_json = json.dumps(inpt)
        inpt_path = os.path.join(TC, "input.json")
        with open(inpt_path, "w") as inpt_file:
            inpt_file.write(inpt_json)

        circuit_compilation, wg_compilation, witness_generation = run_circom(circuit_name)
        clean(circuit_name)

        assert circuit_compilation
        assert wg_compilation
        assert witness_generation


    def test_full_ecdsa(self):
        circuit_name = "full_ecdsa_test"
        m = 0x1a3614c3fc1ed79b2f3ba2864f632ebed77ef241e3774d6421dfd11539c51943
        m_bytes = m.to_bytes(32, 'big')

        privkey = secp256k1.PrivateKey()
        pubkey = privkey.pubkey

        sig = privkey.ecdsa_sign(m_bytes, raw=True)
        verified = pubkey.ecdsa_verify(m_bytes, sig, raw=True)
        assert verified

        r, s = get_rs(sig)

        pubkey_bytes = pubkey.serialize(False)
        Qx_bytes = pubkey_bytes[1:33]
        Qy_bytes = pubkey_bytes[33:]
        Qx = int.from_bytes(Qx_bytes, "big")
        Qy = int.from_bytes(Qy_bytes, "big")

        inpt = {"r": str(r), "s": str(s), "m": str(m), "Qx": str(Qx), "Qy": str(Qy)}

        inpt_json = json.dumps(inpt)
        inpt_path = os.path.join(TC, "input.json")
        with open(inpt_path, "w") as inpt_file:
            inpt_file.write(inpt_json)

        circuit_compilation, wg_compilation, witness_generation = run_circom(circuit_name)
        clean(circuit_name)

        assert circuit_compilation
        assert wg_compilation
        assert witness_generation

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



def getTU(r, s, m, Qx, Qy):
    s256k1 = curve_s256k1.curve
    G = curve_s256k1.generator
    N = curve_s256k1.order
    Q = Point(s256k1, Qx, Qy)
    
    u1 = (m * pow(s, -1, N)) % N
    u2 = (r * pow(s, -1, N)) % N

    R = u1 * G + u2 * Q
    
    T = pow(r, -1, N) * R

    tmp = (pow(r, -1, N) * m) % N
    U = -(tmp * G)

    assert(s * T + U == Q)

    return T.x(), T.y(), U.x(), U.y()


if __name__ == "__main__":
    unittest.main()