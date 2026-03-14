"""Toy lattice-based ABE (educational) implemented with SageMath.

This module demonstrates a minimal Attribute-Based Encryption idea on top of
an LWE-like public-key core. The access policy is the simplest AND policy over
attribute names.

Security notice:
    This code is for learning only and is NOT production-secure.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from typing import Dict, List, Sequence, Set, Tuple

from sage.all import Matrix, Vector, ZZ, random_matrix, vector


@dataclass
class PublicParams:
    q: int
    n: int
    m: int
    A: Matrix
    u: Vector


@dataclass
class MasterSecret:
    s: Vector


@dataclass
class UserSecretKey:
    attrs: Set[str]
    attr_components: Dict[str, int]


@dataclass
class Ciphertext:
    policy: Tuple[str, ...]
    c1: Vector
    c2: int


class ToyLatticeABE:
    """A minimal ABE scheme using LWE-flavored arithmetic.

    Access policy is conjunction (AND): decryption succeeds only if user owns
    every attribute listed in ciphertext.policy.
    """

    def __init__(self, q: int = 4093, n: int = 32, m: int = 64, noise_bound: int = 1):
        self.q = q
        self.n = n
        self.m = m
        self.noise_bound = noise_bound

    def _sample_small_vector(self, length: int) -> Vector:
        entries = [ZZ.random_element(-self.noise_bound, self.noise_bound + 1) for _ in range(length)]
        return vector(ZZ, entries)

    def _mod_q_centered(self, x: int) -> int:
        """Return representative in (-q/2, q/2]."""
        r = int(x % self.q)
        if r > self.q // 2:
            r -= self.q
        return r

    def _hash_to_vec(self, attr: str) -> Vector:
        """Deterministically map attribute string to Z_q^n."""
        chunks: List[int] = []
        counter = 0
        while len(chunks) < self.n:
            digest = hashlib.sha256(f"{attr}|{counter}".encode()).digest()
            for i in range(0, len(digest), 2):
                val = int.from_bytes(digest[i : i + 2], "big") % self.q
                chunks.append(val)
                if len(chunks) == self.n:
                    break
            counter += 1
        return vector(ZZ, chunks)

    def setup(self) -> Tuple[PublicParams, MasterSecret]:
        A = random_matrix(ZZ, self.m, self.n, x=0, y=self.q)
        s = vector(ZZ, [ZZ.random_element(0, self.q) for _ in range(self.n)])
        e = self._sample_small_vector(self.m)
        u = (A * s + e).apply_map(lambda z: z % self.q)

        return PublicParams(q=self.q, n=self.n, m=self.m, A=A, u=u), MasterSecret(s=s)

    def keygen(self, msk: MasterSecret, user_attrs: Sequence[str]) -> UserSecretKey:
        attr_components: Dict[str, int] = {}
        for attr in user_attrs:
            h = self._hash_to_vec(attr)
            attr_components[attr] = int((h.dot_product(msk.s)) % self.q)
        return UserSecretKey(attrs=set(user_attrs), attr_components=attr_components)

    def encrypt(self, pp: PublicParams, msk: MasterSecret, message_bit: int, policy_attrs: Sequence[str]) -> Ciphertext:
        if message_bit not in (0, 1):
            raise ValueError("message_bit must be 0 or 1")

        policy = tuple(sorted(set(policy_attrs)))
        if not policy:
            raise ValueError("policy must contain at least one attribute")

        r = self._sample_small_vector(pp.m)
        e1 = self._sample_small_vector(pp.n)
        e2 = ZZ.random_element(-self.noise_bound, self.noise_bound + 1)

        c1 = (pp.A.transpose() * r + e1).apply_map(lambda z: z % pp.q)

        gamma = 0
        for attr in policy:
            h = self._hash_to_vec(attr)
            gamma = (gamma + int(h.dot_product(msk.s)) % pp.q) % pp.q

        lwe_term = int(pp.u.dot_product(r) + e2)
        c2 = int((lwe_term + gamma + message_bit * (pp.q // 2)) % pp.q)

        return Ciphertext(policy=policy, c1=c1, c2=c2)

    def decrypt(self, pp: PublicParams, usk: UserSecretKey, ct: Ciphertext, msk: MasterSecret) -> int:
        missing = [a for a in ct.policy if a not in usk.attrs]
        if missing:
            raise ValueError(f"User missing required attributes: {missing}")

        # Rebuild gamma from user's attribute components (what ABE provides).
        gamma_user = sum(usk.attr_components[a] for a in ct.policy) % pp.q

        phase = int((ct.c2 - int(ct.c1.dot_product(msk.s)) - gamma_user) % pp.q)
        centered = self._mod_q_centered(phase)

        return 1 if abs(centered) > (pp.q // 4) else 0


def demo() -> None:
    abe = ToyLatticeABE(q=4093, n=24, m=48, noise_bound=1)
    pp, msk = abe.setup()

    alice_key = abe.keygen(msk, ["doctor", "cardiology", "hospitalA"])
    bob_key = abe.keygen(msk, ["nurse", "hospitalA"])

    policy = ["doctor", "hospitalA"]
    ct0 = abe.encrypt(pp, msk, message_bit=0, policy_attrs=policy)
    ct1 = abe.encrypt(pp, msk, message_bit=1, policy_attrs=policy)

    m0 = abe.decrypt(pp, alice_key, ct0, msk)
    m1 = abe.decrypt(pp, alice_key, ct1, msk)

    print("Alice decrypts:", m0, m1)

    try:
        abe.decrypt(pp, bob_key, ct1, msk)
    except ValueError as exc:
        print("Bob decrypt failed as expected:", exc)


if __name__ == "__main__":
    demo()
