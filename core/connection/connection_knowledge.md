# DSoftBus 连接模块知识

## 核心功能

提供统一的设备连接管理能力，支持 BLE、BR、SLE、TCP、WiFi Direct 等多种连接类型。负责连接建立/断开、数据传输、连接信息查询、监听服务、保活与更新。

关键 API：
- `ConnConnectDevice` / `ConnDisconnectDevice` — 建立与断开连接
- `ConnPostBytes` — 发送数据
- `ConnGetConnectionInfo` — 查询连接信息

## 代码地图

```
core/connection/
├── interface/            # 对外接口定义
├── manager/              # 连接管理器（统一接口、连接查找、引用计数）
├── common/               # 公共组件（引用计数、QoS 流控、字节投递）
├── ble/                  # BLE 连接实现
├── br/                   # BR 连接实现
├── sle/                  # SLE 连接实现
├── tcp/                  # TCP 连接实现
├── wifi_direct_cpp/      # WiFi Direct 连接实现
├── proxy/                # 代理连接
├── general/              # 通用连接
└── ipc/                  # IPC 通信
```

架构分层：上层模块 → 连接管理器(manager) → 各协议实现层 → 公共组件(common) → 适配层(adapter)

## 设计约束与规则

- **引用计数**：`ConnDisconnectDevice()` 减少引用计数，BR/BLE 在 `ref<=0` 时触发物理断开；TCP 直接断开不做引用计数
- **连接复用**：同一对设备间多次连接自动复用，返回相同 `connectionId`
- **ConnectOption**：必须先设置 `type` 才能使用对应的 `union` 成员（`bleOption`、`brOption`、`socketOption` 等）
- **模块 ID**：`ConnSetConnectCallback` 注册回调时 `moduleId` 必须唯一
- **BR 频连控制**：短时间内多次 BR 连接会被拒绝；可通过 `BrOption.isDisableBrFrequentConnectControl=true` 禁用（进行本地可靠性测试时需要设置）

## 基本术语

| 术语 | 说明 |
|------|------|
| connectionId | 连接唯一标识，由管理器分配 |
| ConnectOption | 连接参数结构体，含 `type` 和对应协议的 `union` 成员 |
| moduleId | 上层模块标识，注册回调时使用，必须唯一 |

## 子模块知识索引
| 子模块 | 功能 | 源码 |
| --- | --- | --- |
| wifi直连 | 提供p2p直连能力 | `core/connection/wifi_direct_cpp/wifi_direct_cpp_knowledge.md` |