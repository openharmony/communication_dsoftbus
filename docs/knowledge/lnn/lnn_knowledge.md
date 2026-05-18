# DSoftBus 组网模块知识库

> 本目录包含 DSoftBus 组网模块（Bus Center + Authentication）的完整知识库文档。
> **不包含 Lane 相关代码**（lane_manager、lane 选择/分配）。

## 模块全景

组网模块是 DSoftBus 分布式通信的核心，负责设备间的身份认证、网络拓扑构建与维护、连接状态管理和系统事件处理。

架构定位：SDK 接口层 → Bus Center 服务层 → 认证/LNN 子系统 → 适配层

## 子模块索引

### 认证 (Authentication) → [lnn_knowledge_auth.md](lnn_knowledge_auth.md)

- **关键词**：HiChain、Identity Service V2、会话密钥、设备认证、FSM、Meta Auth
- **职责**：设备身份验证、密钥协商、安全通道建立、密钥轮换
- **源码**：`core/authentication/`

### Net Builder → [lnn_knowledge_netbuilder.md](lnn_knowledge_netbuilder.md)

- **关键词**：JoinLNN、LeaveLNN、Connection FSM、Net Builder、Net Ledger、连接异常决策
- **职责**：设备上下线流程、拓扑管理、节点信息同步、双账本管理、连接异常决策
- **源码**：`core/bus_center/lnn/net_builder/` + `net_ledger/` + `service/`

### 心跳保活 (Heartbeat) → [lnn_knowledge_heartbeat.md](lnn_knowledge_heartbeat.md)

- **关键词**：心跳 FSM、Master/Normal 节点、GearMode、离线检测、BLE/UDP/TCP
- **职责**：心跳发送与检测、主从切换、档位调节、设备离线判定
- **源码**：`core/bus_center/lnn/lane_hub/heartbeat/`

### 系统事件管理 (Event Management) → [lnn_knowledge_event.md](lnn_knowledge_event.md)

- **关键词**：EventHandler、WiFi/BT 状态、物理子网、EventMonitor、InfoKey
- **职责**：系统事件注册与分发、WiFi/BT/网络状态监听、节点上下线通知
- **源码**：`core/bus_center/lnn/net_buscenter/` + `service/bus_center_event.c` + `monitor/`

### 组网 SDK 接口 (SDK Interface) → [lnn_knowledge_sdk.md](lnn_knowledge_sdk.md)

- **关键词**：ServerProxy、IPC 通信、公共接口、Extend Obj、MetaNode
- **职责**：SDK 客户端代理、IPC 通信桥接、扩展对象、公共接口定义
- **源码**：`sdk/bus_center/` + `core/bus_center/ipc/` + `interfaces/kits/bus_center/` + `core/bus_center/extend/`

### 内部基础设施 (Infrastructure) → [lnn_knowledge_infra.md](lnn_knowledge_infra.md)

- **关键词**：StateMachine、Map、ConnectionAddr、LNN Init、DiscMgr、ConnMgr、Adapter
- **职责**：通用状态机框架、映射表、连接地址工具、LNN 初始化、设备发现、连接管理、平台适配
- **源码**：`core/bus_center/utils/` + `core/adapter/bus_center/` + `lnn/manager/` + `lnn/conn_mgr/` + `lnn/disc_mgr/`

## 快速路由表

| 开发场景            | 需要阅读的文档           |
| --------------- | ----------------- |
| 设备上线/入网         | auth → netbuilder |
| 设备下线/退网         | netbuilder        |
| 认证失败排查          | auth              |
| 心跳超时/设备离线       | heartbeat         |
| WiFi/BT 状态变化    | event             |
| 事件监听/回调注册       | event             |
| SDK 接口调用/IPC 通信 | sdk               |
| 新增公共接口          | sdk               |
| 使用状态机框架         | infra             |
| 设备发现相关          | infra             |
| 连接地址转换          | infra             |
| 平台适配            | infra             |
| 密钥协商/加密         | auth              |
| 拓扑同步            | netbuilder        |
| 主从节点切换          | heartbeat         |
| 扩展对象/插件         | sdk               |

## 跨模块交互一览

```
SDK 接口 (sdk)
  ↓ IPC 调用
Bus Center 服务层 (netbuilder)
  ↙       ↘
认证 (auth)   系统事件 (event)
  ↓              ↓
心跳 (heartbeat) ←→ 网络状态 (event)

基础设施 (infra) — 被所有模块依赖
  - StateMachine: netbuilder, heartbeat 使用
  - Map: netbuilder, event 使用
  - ConnectionAddr: auth, netbuilder, sdk 使用
  - Adapter: 所有模块平台适配
```

## 初始化顺序

Bus Center 两阶段初始化：

1. **FirstStep**: LocalLedger → EventMonitor → DiscMgr → NetworkMgr → NetBuilder → MetaNode
2. **SecondStep**: LaneHub(含Heartbeat) → DecisionCenter → AuthComponents
