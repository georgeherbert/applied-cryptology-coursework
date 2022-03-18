""" 
Sketch of the attack

1. The elliptic curve is E: y^2 = x^3 + a_4x + a_6 for known a_4 and a_6
2. We choose E' s.t. we can select a point P on E' with ord(P) = r for a small r
3. Since multiplication does not depend on a_6, if we input P to device D, we get [k]P on E' as output
4. Therefore our problem becomes given P, [k]P on E', find k mod ord(P)
5. We repeat with different choices of P and use CRT to compute k
"""

"""
Sagemath stages:

https://crypto.stackexchange.com/questions/71065/invalid-curve-attack-finding-low-order-points

E = EllipticCurve(F, [Mod(-3, p), b]
n = E.order()
n.factor()

P = E.random_pont()
o = P.order()
o.factor()


You can then take these factors and compute P.__mul__(o // factor) which will have the order of the factor
Have now found a point on the invalid elliptic curve with the order

May need to use several of these curves with several factors
Need to find a set of prime factors larger than 2 ** 256

"""