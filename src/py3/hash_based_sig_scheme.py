from os import urandom
from hashlib import sha256


NB_HASH_BITS = 256


def get_hash(b: bytes) -> bytes:
    m = sha256()
    m.update(b)
    return m.digest()


def generate_keys():
    sec_key_pair = ([], [])
    pub_key_pair = ([], [])
    for i in range(2):
        for j in range(NB_HASH_BITS):
            sec_key_pair[i].append(get_hash(urandom(4)))
            pub_key_pair[i].append(get_hash(sec_key_pair[i][j]))

    return (sec_key_pair, pub_key_pair)


def sign_msg(sec_key_pair, msg: str):
    sig = []
    for i, b in enumerate(get_hash(bytes(msg, "utf-8"))):
        for j, bit in enumerate(f"{b:#010b}"[2:]):
            sig.append(sec_key_pair[int(bit)][8*i+j])

    return sig


def verify(pub_key_pair, sig) -> bool:
    for i in range(NB_HASH_BITS):
        sig_hash = get_hash(sig[i])
        if sig_hash != pub_key_pair[0][i] and sig_hash != pub_key_pair[1][i]:
            return False

    return True


if __name__ == "__main__":
    sec_key_pair, pub_key_pair = generate_keys()
    sig = sign_msg(sec_key_pair, "hello world")
    print(f"valid sig: {verify(pub_key_pair, sig)}")
