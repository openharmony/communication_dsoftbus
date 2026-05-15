# DSoftBus 连接模块知识

## 模块基础功能

提供统一的设备连接管理能力，支持 BLE、BR、SLE、TCP、WiFi Direct 等多种连接类型。

**核心功能**：连接管理、数据传输、连接信息查询、监听服务、保活与更新

**对外接口**：`ConnConnectDevice`、`ConnDisconnectDevice`、`ConnPostBytes`、`ConnGetConnectionInfo` 等

---

## 模块组织架构

### 目录结构

```
core/connection/
├── interface/    # 对外接口
├── manager/      # 连接管理器（统一接口、连接查找、引用计数管理）
├── common/       # 公共组件（引用计数、QoS 流控、字节投递）
├── ble/          # BLE 连接
├── br/           # BR 连接
├── sle/          # SLE 连接
├── tcp/          # TCP 连接
├── wifi_direct_cpp/  # WiFi Direct 连接
├── proxy/        # 代理连接
├── general/      # 通用连接
└── ipc/          # IPC 通信
```

### 架构分层

```
上层模块（传输、组网等）
    ↓
连接管理器（manager）
    ↓
各协议连接实现层（BLE | BR | SLE | TCP | WiFi Direct）
    ↓
公共组件（common）
    ↓
适配层（adapter）
```

### 连接类型对比

| 类型 | 带宽 | 功耗 | 延迟 | 适用场景 |
|------|------|------|------|---------|
| BLE | 低 | 很低 | 低 | 低速数据、设备发现 |
| BR | 高 | 高 | 低 | 音频传输 |
| SLE | 低 | 很低 | 低 | 安全通信 |
| TCP | 高 | 中 | 中 | 局域网、大数据 |
| WiFi Direct | 很高 | 中 | 很低 | 高速文件、视频 |

---

## 子模块知识索引
| 子模块 | 功能 | 源码 |
| --- | --- | --- |
| 连接公共 | 提供网络事件监听、引用计数管理功能 | `core/connection/common/common_knowledge.md` |
| 星闪连接 | 提供星闪连接能力 | `core/connection/sle/sle_knowledge.md` |
| wifi直连 | 提供p2p直连能力 | `core/connection/wifi_direct_cpp/wifi_direct_cpp_knowledge.md` |

## 模块设计约束及规则

### 引用计数约束

**规则**：`ConnDisconnectDevice()` 仅减少引用计数，`ref=0 && !needKeepAlive` 才真正断开物理连接

**提醒**：调用 `ConnDisconnectDevice()` 后连接可能仍然存在，需检查引用计数

### 连接复用约束

**规则**：同一设备多次连接自动复用，返回相同 `connectionId`，引用计数递增

**提醒**：如需全新连接，先调用 `ConnDisconnectDeviceAllConn()` 强制断开所有

### 内存管理约束

**规则**：回调中的 `data` 指针必须由接收者使用 `SoftBusFree()` 释放

### BR 频繁连接约束

**规则**：BR 连接有频繁连接控制，短时间内多次连接会被拒绝

**提醒**：可通过 `BrOption.isDisableBrFrequentConnectControl=true` 禁用（谨慎使用）

### WiFi Direct 单例约束

**规则**：P2P 实体是单例，同时只能有一个组

**提醒**：创建新组前必须先调用 `RemoveGroup()`

### ConnectOption 类型约束

**规则**：必须先设置 `type` 才能使用对应的 `union` 成员（`bleOption`、`brOption`、`socketOption` 等）

### 模块 ID 约束

**规则**：使用 `ConnSetConnectCallback` 注册回调时，`moduleId` 必须唯一

---

**关键文件**：
- `core/connection/interface/softbus_conn_interface.h` - 对外接口
- `core/connection/manager/softbus_conn_manager.h` - 连接管理器
- `core/connection/common/common_knowledge.md` - 公共组件知识

---

**文档版本**：v3.0 | **更新**：2026-05-15
