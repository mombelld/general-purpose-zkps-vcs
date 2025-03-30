import binascii

INT_SIZE = 256
CHUNK_SIZE = 32
HASH_WIDTH = 16
FIX_STRING_SIZE = 15

def encode_string(value, pad=True):
    byte_rep = binascii.hexlify(value.encode("utf-8"))
    l = len(byte_rep) // 2
    n_chunks= l // CHUNK_SIZE
    rest = l % CHUNK_SIZE

    out = []
    for i in range(n_chunks):
        out.append(int(byte_rep[i * CHUNK_SIZE * 2: (i + 1) * CHUNK_SIZE * 2], 16))

    if rest > 0:
        out.append(int(byte_rep[n_chunks * CHUNK_SIZE * 2:], 16))

    if pad:
        l = len(out)
        for i in range(l, FIX_STRING_SIZE):
            out.append(0)

    return out

if __name__ == "__main__":
    s = "reference_letter"
    print(encode_string(s))