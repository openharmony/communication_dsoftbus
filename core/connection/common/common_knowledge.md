# 连接公共组件知识

## 模块基础功能

提供连接管理的公共能力：引用计数管理、QoS 流控、字节投递、Socket 抽象

---

## 模块组织架构

```
各协议连接实现层 → 公共组件层（引用计数、QoS 流控、字节投递） → Socket 抽象层
```

---

## 模块设计约束及规则

- **引用计数**：`ref=0 && !needKeepAlive` 才真正断开
- **ConnectOption**：必须先设置 `type` 才能使用对应的 `union` 成员
- **内存管理**：回调中的 `data` 必须由接收者使用 `SoftBusFree()` 释放
- **QoS**：每次发送前检查滑动窗口配额

---

**关键文件**：
- `core/connection/common/include/softbus_conn_common.h` - 公共定义

---

**文档版本**：v3.0 | **更新**：2026-05-15
