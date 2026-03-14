# Toy Lattice-based ABE with SageMath

这是一个**教学用途**的最小实现，演示如何用 `SageMath` 写一个“基于格（LWE 风格）”的属性基加密（ABE）原型。

> ⚠️ 该实现不是生产级安全方案，只用于理解思路。

## 方案直觉

- 使用 LWE 风格公钥项：`A, u = A*s + e (mod q)`。
- 每个属性 `attr` 通过哈希映射到向量 `h_attr ∈ Z_q^n`。
- 主密钥拥有 `s`，并可为用户签发属性密钥分量：`k_attr = <h_attr, s> (mod q)`。
- 加密时给定策略（这里支持最基础的 `AND`：需要拥有所有策略属性）：
  - 生成 LWE 密文 `(c1, c2)`；
  - 由中心授权方（持有 `msk`）在 `c2` 中加入策略偏移 `gamma = Σ<h_attr, s>`；
  - 用户用自己拥有属性对应的 `k_attr` 重构同一个 `gamma` 后可解密。

## 文件

- `toy_lattice_abe.py`: 核心实现与可运行示例。

## 运行方式

确保有 SageMath：

```bash
sage -python toy_lattice_abe.py
```

## 期望输出

你会看到：
- 满足策略属性的用户可以正确恢复消息比特；
- 不满足策略属性的用户会抛出错误（无法计算策略偏移）。
