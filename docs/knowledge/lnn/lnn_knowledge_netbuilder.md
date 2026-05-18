# Net Builder

## 概述

组网构建模块是 DSoftBus 分布式网络的核心，负责设备入网、退网、拓扑管理和节点信息的持久化存储。通过 Bus Center 服务层统一调度，Net Builder 驱动 Connection FSM 完成设备从发现到上线的全生命周期，Net Ledger 提供双账本（本地 + 分布式）存储节点信息，Decision Center 负责连接异常决策和自动清理。

**定位**：组网模块的中枢，串联认证、事件、心跳等子模块完成设备联网。

## 核心功能

- **Bus Center 初始化**：两阶段初始化（FirstStep + SecondStep），按依赖顺序加载各子模块
- **设备入网（JoinLNN）**：完整流程覆盖发现 → 认证 → 同步 → 上线四个阶段
- **设备退网（LeaveLNN）**：支持按地址类型、指定节点、全部退网、无效连接清理四种方式
- **拓扑管理**：维护设备间关系（LnnRelation），支持拓扑信息跨设备同步
- **节点信息同步**：支持能力、连接信息、设备名、主节点选举、拓扑更新、离线等多种同步类型
- **双账本管理**：LocalLedger 管理本设备信息，DistributedLedger 管理远端设备信息
- **连接异常决策**：跟踪 BR 连接异常（page timeout、SDP failure 等），超阈值自动移除设备
- **主节点选举**：WiFi 网络中的 Master 选举机制

## 架构分层

| 层次 | 组件 | 职责 |
|------|------|------|
| 服务层 | bus_center_manager | 两阶段初始化、服务生命周期管理 |
| 决策层 | bus_center_decision_center | 连接异常管理、设备上下线决策 |
| 构建层 | lnn/net_builder | Connection FSM、拓扑构建、同步管理 |
| 存储层 | lnn/net_ledger | 本地账本 + 分布式账本 |

**依赖**：认证模块（入网前置）、事件系统（状态通知）、心跳模块（存活检测）、状态机框架(infra)

**被依赖**：SDK 接口层（上层调用入口）、事件系统（状态变更通知）

## 对外接口

| 接口类别 | 说明 |
|---------|------|
| Bus Center 服务 | 服务初始化/去初始化、设备入网/退网的 SDK 入口 |
| 设备信息查询 | 获取本设备信息、在线节点列表、按 Key 查询节点属性 |
| Net Builder 操作 | 通知发现设备、触发 JoinLNN；按地址/节点/全部退网 |
| 拓扑与状态 | 节点状态变更通知、主节点选举通知 |
| 账本操作 | 在线节点添加/移除、节点信息更新 |
| 连接异常决策 | 异常上报、设备上下线状态处理 |

## 代码位置

| 目录 | 说明 |
|------|------|
| `core/bus_center/service/` | 服务主入口、两阶段初始化、决策中心 |
| `core/bus_center/interface/` | 对外 API 定义、InfoKey 枚举 |
| `core/bus_center/lnn/net_builder/` | Connection FSM、拓扑构建、同步管理 |
| `core/bus_center/lnn/net_ledger/common/` | 账本公共接口、节点信息 |
| `core/bus_center/lnn/net_ledger/local_ledger/` | 本地账本 |
| `core/bus_center/lnn/net_ledger/distributed_ledger/` | 分布式账本 |
| `core/bus_center/lnn/net_ledger/decision_db/` | 决策数据库 |

## 设计约束与规则

| 规则 | 说明 |
|------|------|
| 两阶段初始化 | FirstStep（关键模块）→ SecondStep（非关键模块 + Watchdog） |
| 延迟初始化 | 模块按依赖顺序加载，LocalLedger 优先 |
| Watchdog | 定时监控线程健康 |
| Connection FSM | 消息驱动状态切换，避免竞态 |
| 线程安全 | Ledger 操作使用 mutex 保护 |
| 固定缓冲区 | 所有字符串有固定最大长度，防止溢出 |
| 异步处理 | 非关键操作使用异步消息 |
| 连接异常阈值 | BR 异常超阈值自动移除设备 |
