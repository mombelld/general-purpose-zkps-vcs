import random
from Crypto.Hash import SHA256

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc
b = 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b
n = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551
Gx = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296
Gy = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5

class EccPoint():

    def __init__(self, x, y):
        self.__is_on_curve(x, y)

        self.__x = x
        self.__y = y

    def __neg__(self):
        pass

    def __is_on_curve(self, x, y):
        if x == 0 and y == 0:
            return

        r = (x ** 3 + x * a + b) % p
        l = (y ** 2) % p

        if not l == r:
            raise ValueError("The EC point does not belong to the curve")
        
    def is_inf(self):
        return self.x == 0 and self.y == 0

    @property
    def x(self):
        return self.__x

    @property
    def y(self):
        return self.__y
    
    def __neg__(self):
        negy = (-self.y) % p
        return EccPoint(self.x, negy)
    
    def __add__(self, point):
        if self.is_inf():
            return EccPoint(point.x, point.y)
        
        if point.is_inf():
            return EccPoint(self.x, self.y)
        
        if self == point:
            tmp = pow(2 * self.y, -1, p)
            l = ((3 * self.x ** 2 + a) * tmp) % p

        else:
            tmp = pow(point.x - self.x, -1, p)
            l = ((point.y - self.y) * tmp) % p

        xr = (l ** 2 - self.x - point.x) % p
        yr = (l * (self.x - xr) - self.y) % p

        return EccPoint(xr, yr)

    def __mul__(self, s):
        res = EccInf()
        tmp = EccPoint(self.x, self.y)

        while (s > 0):
            if s % 2 == 1:
                res = res + tmp

            tmp = tmp + tmp
            s = s // 2

        return res
    
    def __rmul__(self, left_hand):
        return self.__mul__(left_hand)
    
    def __eq__(self, point):
        return self.x == point.x and self.y == point.y
    
    def __repr__(self):
        return f"({hex(self.x)}, {hex(self.y)})"

def EccInf():
    return EccPoint(0, 0)

class KeyPair():
    def __init__(self, d, Q):
        self.__d = d
        self.__Q = Q

    @property
    def d(self):
        return self.__d
    
    @property
    def Q(self):
        return self.__Q

def get_key_pair():
    d = random.randrange(1, n)
    G = EccPoint(Gx, Gy)
    Q = d * G

    return KeyPair(d, Q)
    
def sign(d, msg):
    order_bits = n.bit_length()
    order_bytes = (order_bits - 1) // 8 + 1

    G = EccPoint(Gx, Gy)

    h = SHA256.new(msg)
    z = int.from_bytes(h.digest()[:order_bytes])

    r, s = 0, 0

    while True:
        while True:
            k = random.randrange(1, n)
            X = k * G
            r = X.x % n

            if r != 0:
                break

        invk = pow(k, -1, n)
        s =  (invk * (z + r * d)) % n
        if s != 0:
            break

    return (r, s)

if __name__ == "__main__":
    pass