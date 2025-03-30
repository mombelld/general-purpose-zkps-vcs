import ast

BIT_LENGHT = 256
ALPHA = 5
SEC = 128
MIN = 2
MAX = 17

def read_file(t):
    f_name = f"poseidon_params_n{BIT_LENGHT}_t{t}_alpha{ALPHA}_M{SEC}.txt"
    with open(f_name, "r") as file:
        lines = file.readlines()

        constants_line = lines[5]
        constants = [int(c, 16) for c in ast.literal_eval(constants_line)]

        matrix_line = lines[17]
        matrix = [[int(e, 16) for e in r] for r in ast.literal_eval(matrix_line)]

        return constants, matrix
    
def write_file(target, constants, matrix):
    if target == "circom":
        s = "pragma circom 2.1.2;\n\n"
        s += "function ROUND_KEYS(t) {\n"

        for t in range(MIN, MAX + 1):
            cf = "else " if t > MIN else ""
            s += f"{cf}if (t == {t}) {{\n"
            s += f"return {constants[t - MIN]};\n}}"
        
        s += "else {\nassert(0);\nreturn [0];\n}\n}\n\n"

        s += "function MDS_MATRIX(t) {\n"

        for t in range(MIN, MAX + 1):
            cf = "else " if t > MIN else ""
            s += f"{cf}if (t == {t}) {{\n"
            s += f"return {matrix[t - MIN]};\n}}"
        
        s += "else {\nassert(0);\nreturn [[0]];\n}\n}\n\n"

        with open("poseidon_constants.circom", "w") as f:
            f.write(s)
        
    elif target == "python":
        s = "def ROUND_KEYS(t):\n"

        for t in range(MIN, MAX + 1):
            cf = "el" if t > MIN else ""
            s += f"\t{cf}if t == {t}:\n"
            s += f"\t\treturn {constants[t - MIN]}\n"
        
        s += "\telse:\n\t\treturn [0]\n\n"

        s += "def MDS_MATRIX(t):\n"

        for t in range(MIN, MAX + 1):
            cf = "el" if t > MIN else ""
            s += f"\t{cf}if t == {t}:\n"
            s += f"\t\treturn {matrix[t - MIN]}\n"
        
        s += "\telse:\n\t\treturn [[0]]\n\n"

        with open("poseidon_constants.py", "w") as f:
            f.write(s)

    elif target == "java":
        chunk = 4
        s = "package ch.admin.bj.swiyu.issuer.management.zk;\n\nimport java.math.BigInteger;\n\npublic class PoseidonConstants {\n\n"
        s += "public static BigInteger[] getRc(int t) {\n"

        for t in range(MIN, MAX + 1):
            cf = "\t} else " if t > MIN else ""
            s += f"\t{cf}if (t == {t}) {{\n"
            cs = [f"new BigInteger(\"{str(c)}\")" for c in constants[t - MIN]]
            s += f"\t\tBigInteger[] rc =  {{{cs[0]}"
            for i in range(1, len(cs)):
                s+= f",{cs[i]}"
            s += "};\n"
            s += "\t\treturn rc;\n"
        
        s += "\t} else {return null;}\n\t}"

        s += "\n\n\tpublic static BigInteger[][] getMds(int t) {\n"

        # matrix[i] = [[a, a, a], [b, b, b], ...]
        for t in range(MIN, MAX + 1):
            cf = "\t} else " if t > MIN else ""
            s += f"\t{cf}if (t == {t}) {{\n"
            mds = [[f"new BigInteger(\"{str(c)}\")" for c in m] for m in matrix[t - MIN]]
            s += f"\t\tBigInteger[][] mds =  {{{write_java_matrix(mds[0])}"
            for i in range(1, len(mds)):
                s+= f",{write_java_matrix(mds[i])}"
            s += "};\n"
            s += "\t\treturn mds;\n"
        
        s += "\t} else {return null;}\n\t}\n"

        s += "}"
        with open("PoseidonConstants.java", "w") as f:
            f.write(s)
    else:
        raise Exception()
    
def write_java_matrix(m):
    s = f"{{{m[0]}"
    for i in range(1, len(m)):
        s += f",{m[i]}"
    s += "}"

    return s

    
def gen_circom_constants():
    constants = [None for _ in range(MAX - MIN + 1)]
    matrix = [None for _ in range(MAX - MIN + 1)]

    for t in range(MIN, MAX + 1):
        c, m = read_file(t)
        constants[t - MIN] = c
        matrix[t - MIN] = m

    write_file("circom", constants, matrix)

def gen_python_constants():
    constants = [None for _ in range(MAX - MIN + 1)]
    matrix = [None for _ in range(MAX - MIN + 1)]

    for t in range(MIN, MAX + 1):
        c, m = read_file(t)
        constants[t - MIN] = [e for e in c]
        matrix[t - MIN] = [[e for e in r] for r in m]

    write_file("python", constants, matrix)

def gen_java_constants():
    constants = [None for _ in range(MAX - MIN + 1)]
    matrix = [None for _ in range(MAX - MIN + 1)]

    for t in range(MIN, MAX + 1):
        c, m = read_file(t)
        constants[t - MIN] = c
        matrix[t - MIN] = m

    write_file("java", constants, matrix)


if __name__ == "__main__":
    # gen_circom_constants()
    gen_python_constants()
    # gen_java_constants()