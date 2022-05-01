from sage.all import *

p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
a = 0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc

ORDER_MIN = 1000000
ORDER_MAX = 9999999

FF = GF(p)

product = 1

i = 3
while product <= p:
    orders = []
    points = []

    EC = EllipticCurve([FF(a), i])

    gens = EC.gens()
    for gen in gens:
        order = gen.order()
        order_factors = [i[0] for i in order.factor()]
        for factor in order_factors:
            print("Unused order:", factor)
            if factor >= ORDER_MIN and factor <= ORDER_MAX and factor not in orders:
                P = gen * (order // factor)
                print("")
                print("Point order:", factor)
                print("x:", P[0])
                print("y:", P[1])
                print("")
                orders.append(factor)
                points.append((P[0], P[1]))
                product *= factor
            if factor > ORDER_MAX:
                break

    i += 1

print(orders)
print("")

for i, point in enumerate(points):
    print(f'mpz_set_str(points[{i}].x, "{point[0]}", 10); mpz_set_str(points[{i}].y, "{point[1]}", 10);')

