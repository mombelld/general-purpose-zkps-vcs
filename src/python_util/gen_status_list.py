import sys
import random


# Default status list size as per https://www.w3.org/TR/vc-bitstring-status-list/
LIST_LENGTH = 131072

# 2 bits to represent status
ENTRY_SIZE = 2

# Actual list size
TOTAL_SIZE = LIST_LENGTH * ENTRY_SIZE

CHUNK_SIZE = 32
INT_SIZE = 256

def gen_list(list_path, flip_index=0):

    n_chunks = TOTAL_SIZE // INT_SIZE + (1 if TOTAL_SIZE % INT_SIZE != 0 else 0)
    chunks = [random.randint(0, 2 ** INT_SIZE) for _ in range(n_chunks)]
    cs = 2 * CHUNK_SIZE
    with open(list_path, "w") as list_file:
        for c in chunks:
            s = hex(c)[2:]
            sp = "0" * (cs -len(s)) + s
            list_file.write(sp)

def main():
    list_path = sys.argv[1]
    gen_list(list_path)

if __name__ == "__main__":
    main()