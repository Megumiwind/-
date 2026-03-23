"""Toy lattice CP-ABE demo (educational) implemented with SageMath.

This is a structural demo of CP-ABE with:
- an explicit LSSS policy matrix (M, rho),
- setup/keygen/encrypt/decrypt split,
- decryption that does NOT use the MSK.

Security notice:
    This code is for learning only and is NOT production-secure.
"""

from __future__ import annotations

import itertools
from dataclasses import dataclass
from typing import Any, Dict, List, Sequence, Set, Tuple

from sage.all import GF, Matrix, ZZ, matrix, random_matrix, vector


@dataclass
class LSSSPolicy:
    """LSSS policy represented by matrix M and row-to-attribute map rho."""

    M: Matrix
    rho: Tuple[str, ...]


@dataclass
class PublicParams:
    q: int
    n: int
    m: int
    delta: int
    noise_bound: int
    universe: Tuple[str, ...]
    A: Matrix
    u_attrs: Dict[str, Any]


@dataclass
class MasterSecret:
    t_attrs: Dict[str, Any]


@dataclass
class UserSecretKey:
    attrs: Set[str]
    t_attrs: Dict[str, Any]


@dataclass
class Ciphertext:
    policy: LSSSPolicy
    rows: Tuple[Tuple[Any, int], ...]  # (c1_i, d_i)


class ToyLatticeCPABE:
    """A tiny lattice-flavored CP-ABE skeleton with LSSS policy matrix."""

    def __init__(self, q: int = 4093, n: int = 24, m: int = 48, noise_bound: int = 1):
        self.q = q
        self.n = n
        self.m = m
        self.noise_bound = noise_bound
        self.delta = q // 2

    def _sample_small_vector(self, length: int) -> Any:
        vals = [ZZ.random_element(-self.noise_bound, self.noise_bound + 1) for _ in range(length)]
        return vector(ZZ, vals)

    def _mod_centered(self, x: int) -> int:
        r = int(x % self.q)
        if r > self.q // 2:
            r -= self.q
        return r

    @staticmethod
    def and_policy(attrs: Sequence[str]) -> LSSSPolicy:
        """Build an AND policy as an LSSS matrix that requires all attrs.

        For k attributes, M is k x k:
          row1 = [1, 1, 0, ..., 0]
          rowi = [0, ..., -1, 1, ..., 0] for 2 <= i < k
          rowk = [0, ..., -1]
        satisfying: [1,1,...,1] * M = [1,0,...,0].
        """
        uniq = list(dict.fromkeys(attrs))
        if not uniq:
            raise ValueError("AND policy needs at least one attribute")

        k = len(uniq)
        M = matrix(ZZ, k, k)
        if k == 1:
            M[0, 0] = 1
        else:
            M[0, 0] = 1
            M[0, 1] = 1
            for i in range(1, k - 1):
                M[i, i] = -1
                M[i, i + 1] = 1
            M[k - 1, k - 1] = -1

        return LSSSPolicy(M=M, rho=tuple(uniq))

    def setup(self, universe: Sequence[str]) -> Tuple[PublicParams, MasterSecret]:
        universe_uniq = tuple(dict.fromkeys(universe))
        if not universe_uniq:
            raise ValueError("universe must not be empty")

        A = random_matrix(ZZ, self.m, self.n, x=0, y=self.q)

        t_attrs: Dict[str, Any] = {}
        u_attrs: Dict[str, Any] = {}
        for attr in universe_uniq:
            t = vector(ZZ, [ZZ.random_element(0, self.q) for _ in range(self.n)])
            e = self._sample_small_vector(self.m)
            u = (A * t + e).apply_map(lambda z: z % self.q)
            t_attrs[attr] = t
            u_attrs[attr] = u

        pp = PublicParams(
            q=self.q,
            n=self.n,
            m=self.m,
            delta=self.delta,
            noise_bound=self.noise_bound,
            universe=universe_uniq,
            A=A,
            u_attrs=u_attrs,
        )
        msk = MasterSecret(t_attrs=t_attrs)
        return pp, msk

    def keygen(self, pp: PublicParams, msk: MasterSecret, user_attrs: Sequence[str]) -> UserSecretKey:
        attrs = set(user_attrs)
        unknown = attrs.difference(pp.universe)
        if unknown:
            raise ValueError(f"Unknown attributes in keygen: {sorted(unknown)}")

        return UserSecretKey(attrs=attrs, t_attrs={a: msk.t_attrs[a] for a in attrs})

    def encrypt(self, pp: PublicParams, message_bit: int, policy: LSSSPolicy) -> Ciphertext:
        if message_bit not in (0, 1):
            raise ValueError("message_bit must be 0 or 1")
        if len(policy.rho) != policy.M.nrows():
            raise ValueError("policy rho length must equal number of rows of M")
        for attr in policy.rho:
            if attr not in pp.u_attrs:
                raise ValueError(f"Policy contains unknown attribute: {attr}")

        cols = policy.M.ncols()
        v = [ZZ.random_element(0, self.q) for _ in range(cols)]
        v[0] = message_bit * pp.delta
        v_vec = vector(ZZ, v)

        shares: List[int] = []
        for i in range(policy.M.nrows()):
            lam = int(policy.M.row(i).dot_product(v_vec) % self.q)
            shares.append(lam)

        rows: List[Tuple[Any, int]] = []
        for i, attr in enumerate(policy.rho):
            r = self._sample_small_vector(pp.m)
            e1 = self._sample_small_vector(pp.n)
            e2 = ZZ.random_element(-self.noise_bound, self.noise_bound + 1)

            c1 = (pp.A.transpose() * r + e1).apply_map(lambda z: z % pp.q)
            d = int((pp.u_attrs[attr].dot_product(r) + e2 + shares[i]) % pp.q)
            rows.append((c1, d))

        return Ciphertext(policy=policy, rows=tuple(rows))

    def _find_reconstruction_weights(self, policy: LSSSPolicy, owned_attrs: Set[str]) -> List[Tuple[int, int]]:
        """Find rows and coefficients omega s.t. sum omega_i * M_i = [1,0,...,0]."""
        candidate_rows = [i for i, a in enumerate(policy.rho) if a in owned_attrs]
        if not candidate_rows:
            raise ValueError("User has no attributes from policy")

        target = [1] + [0] * (policy.M.ncols() - 1)
        F = GF(self.q)

        for k in range(1, len(candidate_rows) + 1):
            for subset in itertools.combinations(candidate_rows, k):
                M_sub = matrix(F, [list(policy.M.row(i)) for i in subset])
                lhs = M_sub.transpose()  # ncols x k
                b = vector(F, target)
                try:
                    omega = lhs.solve_right(b)
                except Exception:
                    continue
                return [(subset[j], int(omega[j])) for j in range(len(subset))]

        raise ValueError("Attributes do not satisfy policy (no reconstruction vector)")

    def decrypt(self, pp: PublicParams, usk: UserSecretKey, ct: Ciphertext) -> int:
        weights = self._find_reconstruction_weights(ct.policy, usk.attrs)

        rec = 0
        for row_idx, omega_i in weights:
            attr = ct.policy.rho[row_idx]
            c1, d = ct.rows[row_idx]
            t_attr = usk.t_attrs[attr]

            share_est = self._mod_centered(int((d - int(c1.dot_product(t_attr))) % pp.q))
            rec = (rec + omega_i * share_est) % pp.q

        rec_centered = self._mod_centered(rec)
        return 1 if abs(rec_centered) > (pp.delta // 2) else 0


def demo() -> None:
    abe = ToyLatticeCPABE(q=4093, n=24, m=48, noise_bound=1)

    universe = ["doctor", "cardiology", "hospitalA", "nurse"]
    pp, msk = abe.setup(universe)

    alice = abe.keygen(pp, msk, ["doctor", "cardiology", "hospitalA"])
    bob = abe.keygen(pp, msk, ["nurse", "hospitalA"])

    policy = ToyLatticeCPABE.and_policy(["doctor", "hospitalA"])

    ct0 = abe.encrypt(pp, 0, policy)
    ct1 = abe.encrypt(pp, 1, policy)

    print("Alice:", abe.decrypt(pp, alice, ct0), abe.decrypt(pp, alice, ct1))

    try:
        print("Bob:", abe.decrypt(pp, bob, ct1))
    except ValueError as exc:
        print("Bob decrypt failed as expected:", exc)


if __name__ == "__main__":
    demo()
