import p256
import os

I = 32
J = 255
STRIDE = 8

N = 43
K = 6

def gen_precomp_t_arr(T):
    precomp_t = [[None for _ in range(J)] for _ in range(I)]

    pow2 = 2 ** STRIDE
    acc = 1


    for i in range(I):
        incr = acc * T
        P = p256.EccPoint(incr.x, incr.y)
        acc *= pow2
        for j in range(J):
            precomp_t[i][j] = P
            P = P + incr

    out = [[None for _ in range(J + 1)] for _ in range(I)]

    for i in range(I):
        out[i][0] = get_arr_point(0, 0)
        for j in range(J):
            P = precomp_t[i][j]
            out[i][j + 1] = get_arr_point(P.x, P.y)

    return out

def get_arr_point(x, y):
    x = __int_to_array(x)
    y = __int_to_array(y)

    return [[str(e) for e in x], [str(e) for e in y]]


def gen_precomp_t(T, out_path):
    precomp_t = [[None for _ in range(J)] for _ in range(I)]

    pow2 = 2 ** STRIDE
    acc = 1


    for i in range(I):
        incr = acc * T
        P = p256.EccPoint(incr.x, incr.y)
        acc *= pow2
        for j in range(J):
            precomp_t[i][j] = P
            P = P + incr

    # f_name = "get_g_pow_stride8_table"
    f_name = "get_mul_stride8_table"
    header = "\n".join(["pragma circom 2.1.5;", f"function {f_name}(n, k) {{", "assert(n == 43 && k == 6);", f"var powers[{I}][{J + 1}][2][{K}];"])

    s = header
    for i in range(I):
        s += write_point(0, 0, i, 0)
        for j in range(J):
            P = precomp_t[i][j]
            s += write_point(P.x, P.y, i, j + 1)

    s += "return powers;\n"
    s += "}"

    out_file = os.path.join(out_path, "precompT.circom")
    with open(out_file, "w") as f:
        f.write(s)

def write_point(x, y, i, j):
    p0 = f"powers[{i}][{j}]"
    s = ""

    x_arr = __int_to_array(x)
    y_arr = __int_to_array(y)

    for i, e in enumerate(x_arr):
        s += f"{p0}[0][{i}] = {e};\n"

    for i, e in enumerate(y_arr):
        s += f"{p0}[1][{i}] = {e};\n"

    return s

def __int_to_array(x):
    mod = 2 ** N

    ret = []
    x_tmp = x
    for _ in range(K):
        ret.append(x_tmp % mod)
        x_tmp //= mod

    return ret

if __name__ == "__main__":
    T = p256.EccPoint(p256.Gx, p256.Gy)
    print(gen_precomp_t_arr(T))