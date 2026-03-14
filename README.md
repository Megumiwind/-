# Toy Lattice CP-ABE with SageMath

这是一个**教学用途**的最小实现，演示如何用 `SageMath` 写一个结构上更正确的格风格 CP-ABE 原型。

> ⚠️ 本项目只用于学习，不可用于生产安全场景。

## 这版包含什么

- 明确的 **LSSS 策略矩阵**：`LSSSPolicy(M, rho)`。
- 完整流程：`setup / keygen / encrypt / decrypt`。
- **解密不使用 MSK**（用户只用自己属性私钥分量）。
- 提供 `and_policy([...])`，用 LSSS 矩阵表达基础 `AND` 策略。

## 文件

- `toy_lattice_abe.py`：核心实现与 `demo()`。

## 运行

```bash
sage -python toy_lattice_abe.py
```

期望行为：
- 满足策略属性的用户可正确恢复消息比特；
- 不满足策略的用户解密失败（抛出异常）。
