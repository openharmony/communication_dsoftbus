# 内部基础设施 (Infrastructure)

## 概述

基础设施层为组网模块提供通用工具和基础服务。核心组件包括：状态机框架（被 Connection FSM 和 Heartbeat FSM 使用）、Map 映射表、连接地址工具、LNN 初始化注册、设备发现管理（COAP）、连接管理（WiFi Direct）和平台适配层。所有组网子模块均依赖此层。

**定位**：公共基础层，被所有组网子模块依赖。

## 核心功能

### 状态机框架
- 通用 FSM 实现，支持多状态注册、消息驱动切换、延迟消息
- 提供完整的生命周期管理（创建 → 添加状态 → 启动 → 投递消息 → 停止 → 销毁）
- 被组网模块中多个 FSM 复用（Connection FSM、Heartbeat FSM 等）

### Map 映射表
- 哈希映射表实现，支持增删查改和迭代器遍历
- 链地址法处理冲突

### 连接地址工具
- 多种地址格式互转（ConnectionAddr ↔ ConnectOption ↔ AuthConnInfo）
- 地址类型与发现类型映射
- 地址有效性校验和格式化输出

### LNN 初始化
- 通过 dlopen/dlsym 动态加载插件中的初始化注册函数
- 各子模块通过注册机制声明自己的初始化和去初始化函数

### 设备发现管理
- 基于 COAP 协议的设备发现实现
- 提供服务发布和设备扫描的高层 API

### 连接管理
- WiFi Direct 组操作（GO 创建/销毁）

### 平台适配
- 抽象设备信息获取（UDID、设备类型、名称、MAC 地址等）
- 系统信息查询（OS 类型/版本、设备版本/型号）
- 网络信息（WiFi IP 地址）
- 安全信息（设备安全等级）
- 设备类型映射（系统类型 ↔ SoftBus 标准类型字符串）

## 架构分层

| 层次 | 组件 | 职责 |
|------|------|------|
| 通用框架 | utils (StateMachine, Map, etc.) | 通用数据结构和算法 |
| 地址工具 | utils (connection_addr_utils) | 多种地址格式转换 |
| 初始化 | lnn/manager (softbus_lnn_init) | 动态加载初始化函数 |
| 发现管理 | lnn/disc_mgr | COAP 设备发现 |
| 连接管理 | lnn/conn_mgr | WiFi Direct 组操作 |
| 平台适配 | adapter/bus_center | 设备信息和平台能力抽象 |

**依赖**：SoftBus Looper 消息机制

**被依赖**：所有组网子模块

## 对外接口

| 接口类别 | 说明 |
|---------|------|
| 状态机生命周期 | 状态机的初始化、销毁 |
| 状态管理 | 添加状态、启动/停止、状态切换 |
| 消息投递 | 即时/延迟消息投递、消息移除 |
| Map 操作 | 增删查、迭代器遍历 |
| 地址转换 | 多种地址格式互转和校验 |
| 设备发现 | 初始化发现管理、服务发布/停止、设备扫描/停止 |
| 平台适配 | 获取设备信息、网络信息、安全等级 |

## 代码位置

| 目录 | 说明 |
|------|------|
| `core/bus_center/utils/include/` | 状态机、Map、地址工具等头文件 |
| `core/bus_center/utils/src/` | 实现文件 |
| `core/bus_center/lnn/manager/` | LNN 初始化注册 |
| `core/bus_center/lnn/disc_mgr/` | COAP 设备发现管理 |
| `core/bus_center/lnn/conn_mgr/` | WiFi Direct 连接管理 |
| `core/adapter/bus_center/` | 平台适配实现 |
| `adapter/common/include/bus_center_adapter.h` | 适配接口定义 |

## 设计约束与规则

| 规则 | 说明 |
|------|------|
| 消息驱动 | 状态机所有状态切换通过 Looper 消息，避免直接回调 |
| 回调顺序 | 状态回调严格按 enter → process(多次) → exit 执行 |
| Map 非线程安全 | Map 操作需外部加锁保护 |
| 固定缓冲区 | 所有字符串使用固定长度缓冲区，防止溢出 |
| 动态加载 | LNN 初始化函数通过 dlopen/dlsym 动态加载 |
| 设备类型映射表固定 | 新增设备类型需修改适配层 |
