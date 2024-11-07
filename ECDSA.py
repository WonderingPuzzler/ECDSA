import random
import hashlib


# Function to compute modular inverse
def modInverse(x, p):
    return pow(x, p - 2, p)


# Point addition on the elliptic curve
def pointAdd(Q, N, p, a):
    if Q == N:
        return pointDouble(Q, p, a)


    x, y = Q
    x1, y1 = N

    # s = (y1 - y) / (x1 - x) mod p
    s = ((y1 - y) * modInverse(x1 - x, p)) % p

    # x2 = s^2 - x - x1 mod p
    x2 = (s ** 2 - x - x1) % p

    # y2 = s(x - x2) - y mod p
    y2 = (s * (x - x2) - y) % p

    return (x2, y2)


# Point doubling on the elliptic curve
def pointDouble(P, p, a):
    x, y = P

    # s = (3 * x^2 + a) / (2 * y) mod p
    s = ((3 * x ** 2 + a) * modInverse(2 * y, p)) % p

    # x2 = s^2 - 2 * x mod p
    x2 = (s ** 2 - 2 * x) % p

    # y2 = s(x - x2) - y mod p
    y2 = (s * (x - x2) - y) % p

    return (x2, y2)


# Scalar multiplication on the elliptic curve (dG = public key)
def scalarMultiplication(privateKey, basePoint, p, a):
    N = basePoint
    Q = (None, None)

    while privateKey > 0:
        if privateKey & 1:
            if Q == (None, None):
                Q = N
            else:
                Q = pointAdd(Q, N, p, a)
        N = pointDouble(N, p, a)
        privateKey >>= 1

    return Q


# Hash the data using SHA-256
def hashData(data):
    dataHash = hashlib.sha256(data.encode()).hexdigest()
    intHash = int(dataHash, 16)
    return intHash


# Generate ECDSA signature
def signature(privateKey, basePoint, p, a, n, data):
    d = privateKey  # Private key
    z = hashData(data)

    # Random integer k such that 1 <= k <= n-1
    k = random.randint(1, n - 1)

    # R = k * G
    R = scalarMultiplication(k, basePoint, p, a)
    Rx = R[0]

    # r = R_x mod n
    r = Rx % n

    # s = k^(-1) * (z + d * r) mod n
    k = modInverse(k, n)
    s = (k * (z + d * r)) % n

    return (r, s)


# Verifies that the ECDSA signature is valid
def verify(publicKey, basePoint, p, a, n, z, signature):
    r, s = signature
    z = z  # Message hash



    # sz1 = (s^(-1) * z) mod n
    sz1 = (modInverse(s, n) * z) % n

    # sz2 = (s^(-1) * r) mod n
    sz2 = (modInverse(s, n) * r) % n

    # R = sz1 * G(basePoint) + sz2 * Q(publicKey)
    R1 = scalarMultiplication(sz1, basePoint, p, a)
    R2 = scalarMultiplication(sz2, publicKey, p, a)

    # R = R1 + R2
    R = pointAdd(R1, R2, p, a)


    Rx = R[0] % n
    return Rx == r


def main():
    # Parameters for the Elliptic Curve (SECP256R1)
    p = (2 ** 256 - 2 ** 224 + 2 ** 192 + 2 ** 96 - 1)
    a = -3

    # Base point (G) coordinates
    GxCord = 48439561293906451759052585252797914202762949526041747995844080717082404635286
    GyCord = 36134250956749795798585127919587881956611106672985015071877198253568414405109
    basePoint = (GxCord, GyCord)

    # Number of curve points
    n = 115792089210356248762697446949407573529996955224135760342422259061068512044369

    # Random private key
    privateKey = random.randint(1, n - 1)

    # Public key = privateKey * basePoint
    publicKey = scalarMultiplication(privateKey, basePoint, p, a)

    data = ("This is a very important piece of information that needs to be sent. Be a shame if someone... decrypted your cryptographic algorithm, hm? "
            "You wouldn't want that, would you? Hand over your bits, pal. All of them. 0s too.")

    z = hashData(data)

    # Generate signature
    signatory = signature(privateKey, basePoint, p, a, n, data)

    # Verify signature
    validity = verify(publicKey, basePoint, p, a, n, z, signatory)

    print(f"Private Key: {privateKey}")
    print(f"Public Key: {publicKey}\n")
    print(f"Signature: {signatory}\n")
    print(f"Signature Validity: {validity}!")


if __name__ == "__main__":
    main()
