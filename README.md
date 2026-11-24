主密钥派生子密钥之后，两个不同业务拿到了一模一样的密钥，隔离彻底失效：提取阶段盐为空时直接跳过而不是使用默认盐；扩展阶段把计数器放在块尾部而不是块首；扩展长度上限不校验，超长输出被静默截断；上下文只参与首块，后续块忽略上下文；用途未参与派生，不同用途拿到同一密钥；长度为零时返回空字节而不报错；分发时复用首块，多个上下文共享前缀；校验用普通等号比较；策略校验不检查上下文是否为空；批量派生复用中间结果，第二个请求沿用第一个请求的上下文。kdf/tree.py 是核心，tests/unit/test_tree.py 15个红。要修的是：按上面的顺序把 10 个缺陷逐个修掉。

# sec-kdf-tree

安全出题仓库：主密钥树派生与业务域隔离。当前只提供契约桩与红色测试，`kdf/tree.py` 中恰好有 8 个桩函数，全部抛出 `NotImplementedError`；`tests` 目录中的 15 条测试是唯一验收标准。

## 仓库布局

```text
sec-kdf-tree/
  README.md
  conftest.py
  kdf/__init__.py
  kdf/tree.py
  tests/unit/test_tree.py
  tests/behaviour/test_tree_edge.py
```

## 运行方式

在仓库根目录执行：

```text
python -m pytest tests -q
```

当前预期结果为 `15 failed`，且 0 个 collection error；15 个失败必须全部来自 `NotImplementedError`。完成 `kdf/tree.py` 后应变为 `15 passed`。

## 派生规范

所有函数只使用 Python 标准库的 `hmac` 与 `hashlib`，摘要固定为 SHA-256，结果全部为确定性字节串。不得使用随机数、时钟、进程级可变状态、网络或第三方依赖。

公开常量：

```text
DEFAULT_SALT = bytes(range(32))
MAX_LENGTH = 255 * 32 = 8160
PREFIX = b"GSB-KDF-TREE-v1"
SPLIT_PURPOSE = b"split"
```

### 提取阶段

```text
extract(salt, ikm) = HMAC-SHA256(
    key = salt if salt != b"" else DEFAULT_SALT,
    msg = ikm,
)
```

盐为空字节串时必须替换为 `DEFAULT_SALT`，不能改用空密钥，也不能跳过提取。返回固定 32 字节。

### 扩展阶段

设 `n = ceil(length / 32)`，`T_0 = b""`，对 `i = 1 .. n` 计算：

```text
T_i = HMAC-SHA256(
    key = prk,
    msg = bytes([i]) + info + T_(i-1),
)
```

返回值是 `T_1 + T_2 + ... + T_n` 的前 `length` 字节。计数器单字节位于每一块块首；`info` 必须参与每一块的输入，而不是只参与首块。`length` 必须是 1 到 `MAX_LENGTH` 之间的整数，超过 255 个块或小于等于 0 都抛出 `ValueError`，不得静默截断。

### 两步组合与业务域

```text
derive(secret, salt, info, length):
    prk = extract(salt, secret)
    return expand(prk, info, length)
```

`derive` 对零长度、负长度和超过 `MAX_LENGTH` 的长度抛出 `ValueError`。

```text
derive_key(secret, context, purpose, length):
    encoded = PREFIX
        + len(context).to_bytes(2, "big")
        + context
        + len(purpose).to_bytes(2, "big")
        + purpose
    return derive(secret, b"", encoded, length)
```

`context` 与 `purpose` 必须都是非空 `bytes`，且各自长度不超过 65535。两段两字节大端长度前缀用于消除拼接歧义，`context` 与 `purpose` 必须同时影响所有输出块。

### 分发、校验与策略

```text
split(secret, contexts) -> {context: derive_key(secret, context, b"split", 32)}
```

每个上下文独立派生 32 字节；上下文不得为空、不得重复；任何两个结果不得相同，也不得共享首块前缀。输入顺序不影响结果。

```text
verify_derivation(secret, context, purpose, candidate):
    expected = derive_key(secret, context, purpose, 32)
    return hmac.compare_digest(expected, candidate)
```

必须使用标准库的恒定时间比较（`hmac.compare_digest` 或等价的 `secrets.compare_digest`），不得使用普通 `==`。`candidate` 不是 32 字节时返回 `False`。

`validate_policy(policy)` 检查一个策略映射，并返回问题代码列表，顺序固定为：

1. `length-above-limit`：`policy["length"] > MAX_LENGTH`。
2. `context-empty`：`context` 缺失、为 `None` 或为空字节串。
3. `purpose-missing`：`purpose` 缺失、为 `None` 或为空字节串。

合法策略返回空列表，例如：

```python
{"length": 32, "context": b"tenant-a", "purpose": b"encrypt"}
```

`kdf_batch(requests, policy)` 中，`policy` 提供 `length`、`context`、`purpose` 默认值；每个请求是包含 `id`、`secret` 以及可选覆盖字段 `context`、`purpose`、`length` 的映射。每个请求先与策略默认值合并，再独立调用 `validate_policy`；任何问题都抛出 `ValueError`。不同请求的 `secret`、`context`、`purpose`、`length` 和中间结果绝不可复用，第二个请求也不得沿用第一个请求的上下文。返回 `{id: derived_bytes}`，`id` 必须唯一，空请求序列返回空字典。

## 十个缺陷与契约测试

| 序号 | 缺陷 | 对应契约测试 |
| --- | --- | --- |
| 1 | 空盐时跳过提取而不是使用默认盐 | `test_extract_uses_default_salt_when_salt_is_empty` |
| 2 | 扩展计数器位于块尾而不是块首 | `test_expand_puts_counter_at_block_head` |
| 3 | 扩展长度上限不校验，超长输出被截断 | `test_expand_rejects_length_above_maximum` |
| 4 | 上下文只参与首块，后续块忽略上下文 | `test_expand_binds_info_in_every_block` |
| 5 | 用途未参与派生，不同用途得到同一密钥 | `test_derive_key_separates_purpose` |
| 6 | 零长度返回空字节而不报错 | `test_derive_rejects_zero_length` |
| 7 | 分发时复用首块，多个上下文共享前缀 | `test_split_does_not_reuse_first_block` |
| 8 | 校验使用普通等号而不是恒定时间比较 | `test_verify_derivation_uses_constant_time_compare` |
| 9 | 策略校验不检查上下文为空 | `test_validate_policy_reports_empty_context` |
| 10 | 批量派生复用中间结果，沿用首个请求上下文 | `test_kdf_batch_keeps_requests_independent` |

## 测试拆分布局说明（合计 15 条）

`tests/unit/test_tree.py`：10 条契约测试，按题面顺序一一对应 10 个缺陷：

1. `test_extract_uses_default_salt_when_salt_is_empty`
2. `test_expand_puts_counter_at_block_head`
3. `test_expand_rejects_length_above_maximum`
4. `test_expand_binds_info_in_every_block`
5. `test_derive_key_separates_purpose`
6. `test_derive_rejects_zero_length`
7. `test_split_does_not_reuse_first_block`
8. `test_verify_derivation_uses_constant_time_compare`
9. `test_validate_policy_reports_empty_context`
10. `test_kdf_batch_keeps_requests_independent`

`tests/behaviour/test_tree_edge.py`：5 条边界测试，分别检查固定字节向量、同输入同输出、不同上下文必不同、超长请求被拒绝、两批独立派生与单独派生一致：

1. `test_fixed_inputs_match_known_vectors`
2. `test_same_inputs_are_byte_stable`
3. `test_different_contexts_produce_different_keys`
4. `test_overlong_requests_are_rejected`
5. `test_independent_batches_match_individual_derivations`

两部分合计 15 条测试。

## tests 不可修改

`tests` 目录及其中的 15 条测试不可修改，只能修改 `kdf/tree.py`。测试不依赖网络、时间、随机数或第三方包；测试中的十六进制字节和长度边界均为冻结契约。

## 字段表

| 字段 | 取值 |
| --- | --- |
| 所属领域 | 安全 |
| 子方向 | 漏洞检测与攻防 |
| 任务类型 | Bugfix |
| 语言/框架 | Python 3, pytest |
| 环境可复现等级 | 无外部依赖 |