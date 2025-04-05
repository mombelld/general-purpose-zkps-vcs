import binascii
import base64
import json
import os
import sys
import time
import dateutil.parser as date_parser
import gen_status_list
import datetime
from Crypto.Hash import SHA256

# Local imports
import poseidon_hash
import p256
import gen_precomp_t

INT_SIZE = 256
CHUNK_SIZE = 32
HASH_WIDTH = 16
FIX_STRING_SIZE = 15


def decode_vc(vc_path):
    with open(vc_path, "r") as vc_file:
        vc = vc_file.read()
        # Decode payload
        encoded_payload = vc.split(".")[1]
        decoded_payload = base64.urlsafe_b64decode(
            encoded_payload + '==').decode('utf-8')
        payload = json.loads(decoded_payload)
        # Decode disclosures
        disclosures = {}
        encoded_disclosures_list = vc.split("~")[1:-1]
        for e in encoded_disclosures_list:
            decoded_disclosure = base64.urlsafe_b64decode(
                e + '==').decode('utf-8')
            disclosure = json.loads(decoded_disclosure)
            disclosure_name = disclosure[1]
            disclosures[disclosure_name] = disclosure[2]

        return payload | disclosures


def add_auxiliary_input(aux_input_path, input_data):
    with open(aux_input_path, "r") as aux_input_file:
        aux_input = json.loads(aux_input_file.read())

        for ai in aux_input.keys():
            input_data[ai] = aux_input[ai]

    input_data["now_timestamp"] = str(int(time.time()))

    return input_data


def get_proof_inputs(proof_metadata_path):
    with open(proof_metadata_path, "r") as proof_metadata_file:
        proof_metadata = json.loads(proof_metadata_file.read())
        return proof_metadata["inputs"], proof_metadata["order"], proof_metadata["type"], proof_metadata["prefix"]


def encode_value(value, typ, pad=True, date_offset=0):
    if typ == "number":
        return [int(value)]

    elif typ == "string":
        byte_rep = binascii.hexlify(value.encode("utf-8"))
        l = len(byte_rep) // 2
        n_chunks = l // CHUNK_SIZE
        rest = l % CHUNK_SIZE

        out = []
        for i in range(n_chunks):
            out.append(
                int(byte_rep[i * CHUNK_SIZE * 2: (i + 1) * CHUNK_SIZE * 2], 16))

        if rest > 0:
            out.append(int(byte_rep[n_chunks * CHUNK_SIZE * 2:], 16))

        if pad:
            l = len(out)
            for i in range(l, FIX_STRING_SIZE):
                out.append(0)

        return out

    elif typ == "date" or typ == "date-time":
        if isinstance(value, int):
            return [value + date_offset]
        else:
            dt = date_parser.parse(value)
            timestamp_utc = dt.replace(
                tzinfo=datetime.timezone.utc).timestamp()
            return [int(timestamp_utc) + date_offset]
    else:
        return None


def encode_claims(claims, order, types, date_offset):
    encoded_names = []
    encoded_values = []
    hashed_claims = []
    for i, claim_name in enumerate(order):
        claim_value = claims[claim_name]
        typ = types[i]
        encoded_name = encode_value(claim_name, "string", False)
        encoded_value = encode_value(claim_value, typ, date_offset=date_offset)
        h_name = poseidon_hash.hash(encoded_name)
        h_claim = poseidon_hash.hash([h_name] + encoded_value)

        if typ == "number" or "date" in typ:
            encoded_value = encoded_value[0]

        encoded_names.append(h_name)
        encoded_values.append(encoded_value)
        hashed_claims.append(str(h_claim))

    return encoded_names, encoded_values, hashed_claims


def load_status_list(status_list_name):
    base_path = os.path.dirname(os.path.abspath(__file__))
    status_list_path = os.path.join(
        base_path, "..", "..", "status_list", status_list_name)

    status_list = b""
    with open(status_list_path, "r") as status_list_file:
        status_list = status_list_file.read()

    n_chunks = gen_status_list.TOTAL_SIZE // INT_SIZE + \
        (1 if gen_status_list.TOTAL_SIZE % INT_SIZE != 0 else 0)
    status_list_chunk = [0 for _ in range(n_chunks)]

    chunk_length = CHUNK_SIZE * 2
    for i in range(n_chunks):
        chunk = status_list[i * chunk_length:(i + 1) * chunk_length]
        status_list_chunk[i] = str(int("0x" + chunk, 16))

    return status_list_chunk


def hardware_binding(hb_key_pair_path, input_data, prefix):
    hb_key_par_file = None
    with open(hb_key_pair_path, "r") as proof_metadata_file:
        hb_key_par_file = json.loads(proof_metadata_file.read())

    order = p256.n

    order_bits = order.bit_length()
    order_bytes = (order_bits - 1) // 8 + 1

    nonce = input_data["now_timestamp"].encode("utf-8")
    tmp = hb_key_par_file["sk"]
    sk = int(f"0x{tmp}", 16)
    (r, s) = p256.sign(sk, nonce)

    h = SHA256.new(nonce)
    z = int.from_bytes(h.digest()[:order_bytes], byteorder="big")

    G = p256.EccPoint(p256.Gx, p256.Gy)
    u1 = (z * pow(s, -1, order)) % order
    u2 = (r * pow(s, -1, order)) % order

    Q = sk * G
    R = u1 * G + u2 * Q

    T = pow(r, -1, order) * R
    tmp = (pow(r, -1, order) * z) % order
    U = -(tmp * G)

    pwrs = gen_precomp_t.gen_precomp_t_arr(T)

    input_data[f"{prefix}hb_ux"] = str(U.x)
    input_data[f"{prefix}hb_uy"] = str(U.y)
    input_data[f"{prefix}hb_powers"] = pwrs
    input_data[f"{prefix}hb_R_x"] = str(R.x)
    input_data[f"{prefix}hb_R_y"] = str(R.y)
    input_data[f"{prefix}hb_r"] = str(r)
    input_data[f"{prefix}hb_s"] = str(s)

    return input_data


def main():
    proof_path = sys.argv[1]
    n_credentials = int(sys.argv[2])
    credential_paths = ["" for _ in range(n_credentials)]
    for i in range(n_credentials):
        credential_paths[i] = sys.argv[i + 3]

    input_data = {}
    proof_inputs_l, inputs_order_l, input_types_l, prefix_l = get_proof_inputs(
        os.path.join(proof_path, "proof_metadata.json"))

    input_data = add_auxiliary_input(os.path.join(
        proof_path, "auxiliary_inputs.json"), input_data)
    for i, credential_path in enumerate(credential_paths):
        claims = decode_vc(credential_path)
        proof_inputs = proof_inputs_l[i]
        inputs_order = inputs_order_l[i]
        input_types = input_types_l[i]
        prefix = prefix_l[i]

        date_offset = claims["date_offset"]
        status_list_uri = claims["status_list_uri"]
        claim_names, claim_values, hashed_claims = encode_claims(
            claims, inputs_order, input_types, date_offset)
        for inp in proof_inputs:
            if inp == "status_list_uri":
                input_data[f"{prefix}status_list"] = load_status_list(
                    status_list_uri)
            if inp in inputs_order:
                idx = inputs_order.index(inp)
                claim_name = claim_names[idx]
                tmp_claim_value = claim_values[idx]
                if isinstance(tmp_claim_value, list):
                    claim_value = [str(v) for v in tmp_claim_value]
                else:
                    claim_value = str(tmp_claim_value)
                input_data[f"{prefix}{inp}_name"] = str(claim_name)
                input_data[f"{prefix}{inp}_value"] = claim_value

            else:
                input_data[f"{prefix}{inp}"] = claims[inp]

        input_data[f"{prefix}hashed_claims"] = hashed_claims

        # Check if we're doing hardware binding and if so add nonce signature and additional data
        if "cnf_jwk_x" in proof_inputs:
            input_data = hardware_binding(os.path.join(
                proof_path, "hb_keypair.json"), input_data, prefix)

    with open(os.path.join(proof_path, "input.json"), "w") as input_file:
        input_file.write(json.dumps(input_data))


if __name__ == "__main__":
    main()
