

# This file was *autogenerated* from the file sswu_generic.sage
from sage.all_cmdline import *   # import sage library

_sage_const_0 = Integer(0); _sage_const_1 = Integer(1); _sage_const_2 = Integer(2); _sage_const_4 = Integer(4); _sage_const_3 = Integer(3); _sage_const_256 = Integer(256); _sage_const_32 = Integer(32); _sage_const_9 = Integer(9); _sage_const_8 = Integer(8); _sage_const_7 = Integer(7); _sage_const_6 = Integer(6); _sage_const_0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533 = Integer(0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533); _sage_const_1771 = Integer(1771)#!/usr/bin/sage
# vim: syntax=python

import sys
try:
    from sagelib.common import CMOV
    from sagelib.generic_map import GenericMap
    from sagelib.z_selection import find_z_sswu
except ImportError:
    sys.exit("Error loading preprocessed sage files. Try running `make clean pyfiles`")

class GenericSSWU(GenericMap):
    def __init__(self, F, A, B):
        self.name = "SSWU"
        self.F = F
        self.A = F(A)
        self.B = F(B)
        if self.A == _sage_const_0 :
            raise ValueError("S-SWU requires A != 0")
        if self.B == _sage_const_0 :
            raise ValueError("S-SWU requires B != 0")
        self.Z = find_z_sswu(F, F(A), F(B))
        self.E = EllipticCurve(F, [F(A), F(B)])

        # constants for straight-line impl
        self.c1 = -F(B) / F(A)
        self.c2 = -F(_sage_const_1 ) / self.Z

        # values at which the map is undefined
        # i.e., when Z^2 * u^4 + Z * u^2 = 0
        # which is at u = 0 and when Z * u^2 = -1
        self.undefs = [F(_sage_const_0 )]
        if self.c2.is_square():
            ex = self.c2.sqrt()
            self.undefs += [ex, -ex]

    def not_straight_line(self, u):
        inv0 = self.inv0
        is_square = self.is_square
        sgn0 = self.sgn0
        sqrt = self.sqrt
        u = self.F(u)
        A = self.A
        B = self.B
        Z = self.Z

        tv1 = inv0(Z**_sage_const_2  * u**_sage_const_4  + Z * u**_sage_const_2 )
        x1 = (-B / A) * (_sage_const_1  + tv1)
        if tv1 == _sage_const_0 :
            x1 = B / (Z * A)
        gx1 = x1**_sage_const_3  + A * x1 + B
        x2 = Z * u**_sage_const_2  * x1
        gx2 = x2**_sage_const_3  + A * x2 + B
        if is_square(gx1):
            x = x1
            y = sqrt(gx1)
        else:
            x = x2
            y = sqrt(gx2)
        if sgn0(u) != sgn0(y):
            y = -y
        return (x, y)

    def straight_line(self, u):
        inv0 = self.inv0
        is_square = self.is_square
        sgn0 = self.sgn0
        sqrt = self.sqrt
        u = self.F(u)
        A = self.A
        B = self.B
        Z = self.Z
        c1 = self.c1
        c2 = self.c2

        tv1 = Z * u**_sage_const_2 
        tv2 = tv1**_sage_const_2 
        x1 = tv1 + tv2
        x1 = inv0(x1)
        e1 = x1 == _sage_const_0 
        x1 = x1 + _sage_const_1 
        x1 = CMOV(x1, c2, e1)    # If (tv1 + tv2) == 0, set x1 = -1 / Z
        x1 = x1 * c1      # x1 = (-B / A) * (1 + (1 / (Z^2 * u^4 + Z * u^2)))
        gx1 = x1**_sage_const_2 
        gx1 = gx1 + A
        gx1 = gx1 * x1
        gx1 = gx1 + B             # gx1 = g(x1) = x1^3 + A * x1 + B
        x2 = tv1 * x1            # x2 = Z * u^2 * x1
        tv2 = tv1 * tv2
        gx2 = gx1 * tv2           # gx2 = (Z * u^2)^3 * gx1
        e2 = is_square(gx1)
        x = CMOV(x2, x1, e2)    # If is_square(gx1), x = x1, else x = x2
        y2 = CMOV(gx2, gx1, e2)  # If is_square(gx1), y2 = gx1, else y2 = gx2
        y = sqrt(y2)
        e3 = sgn0(u) == sgn0(y)  # Fix sign of y
        y = CMOV(-y, y, e3)
        return (x, y)

p = _sage_const_2 **_sage_const_256  - _sage_const_2 **_sage_const_32  - _sage_const_2 **_sage_const_9  - _sage_const_2 **_sage_const_8  - _sage_const_2 **_sage_const_7  - _sage_const_2 **_sage_const_6  - _sage_const_2 **_sage_const_4  - _sage_const_1 
F = GF(p)
A = F(_sage_const_0 )
B = F(_sage_const_7 )
# Ap and Bp define isogenous curve y^2 = x^3 + Ap * x + Bp
Ap = F(_sage_const_0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533 )
Bp = F(_sage_const_1771 )

GenericSSWU(F, Ap, Bp)

