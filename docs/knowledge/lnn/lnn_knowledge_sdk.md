# 组网 SDK 接口 (SDK Interface)

## 概述

组网 SDK 接口层是应用层与组网 Core 服务之间的通信桥梁。提供标准化的公共 API（函数指针表），通过 OpenHarmony IPC 框架实现跨进程调用。针对 mini/small/standard 三种系统类型提供不同 IPC 实现。通过 BusCenterExObj 扩展对象支持插件化的高级能力（如发现策略、资源冲突检测），插件通过 dlopen/dlsym 动态加载。

**定位**：应用层访问组网能力的唯一入口。

## 核心功能

- **SDK 代理**：封装 IPC 调用细节，为应用层提供透明的远程调用能力
- **多系统适配**：mini（轻量级）、small（精简版）、standard（完整版）三种 IPC 实现
- **公共接口定义**：通过函数指针表定义标准化 API
- **设备入网/退网**：JoinLNN / LeaveLNN 的 IPC 代理
- **设备信息查询**：获取本设备信息、在线节点列表、按 Key 查询节点属性
- **发布/发现代理**：服务发布和设备发现的 IPC 代理
- **时间同步代理**：跨设备时间同步的 IPC 代理
- **Meta 节点管理**：MetaNode 的创建/销毁/查询
- **数据级别管理**：数据安全级别的设置和变更通知
- **扩展对象**：插件化高级能力（发现策略、MetaNode、资源冲突检测、心跳控制）
- **事件回调**：Core 向 SDK 推送设备上下线、发现结果等事件通知

## 架构分层

| 层次 | 组件 | 职责 |
|------|------|------|
| 公共接口 | interfaces/kits/bus_center | 标准化 API 定义（函数指针表、InfoKey、事件回调） |
| SDK 代理 | sdk/bus_center/ipc | 客户端 IPC 代理（mini/small/standard） |
| Core Stub | core/bus_center/ipc | 服务端 IPC 入口（反序列化 → 调用服务层） |
| 扩展对象 | core/bus_center/extend | C++ 扩展接口（Proxy/Stub 模式，动态加载插件） |
| 初始化 Stub | core/frame/small | 小系统服务端 Stub |

**依赖**：OpenHarmony IPC 框架（IRemoteStub/IRemoteBroker）、DSoftBus Core 服务

**被依赖**：应用层（直接调用方）

## 对外接口

| 接口类别 | 说明 |
|---------|------|
| 设备入网/退网 | JoinLNN / LeaveLNN 操作 |
| 设备信息查询 | 本设备信息、在线节点列表、按 Key 查询/设置属性 |
| 服务发布 | 发布/停止发布服务 |
| 设备发现 | 发现/停止发现设备 |
| 时间同步 | 跨设备时间同步的启停 |
| Meta 节点 | MetaNode 的创建/销毁/查询 |
| 数据级别 | 数据安全级别设置和变更通知 |
| 扩展能力 | 发现策略、预链接参数、资源冲突检测、心跳控制 |
| Core → SDK 回调 | 入网/退网结果、设备上下线、发现设备、时间同步结果通知 |

## 代码位置

| 目录 | 说明 |
|------|------|
| `interfaces/kits/bus_center/` | 公共接口定义（函数指针表、InfoKey、事件回调） |
| `sdk/bus_center/ipc/` | SDK 客户端代理（mini/small/standard） |
| `core/bus_center/ipc/` | 服务端 IPC Stub（mini/small/standard） |
| `core/bus_center/extend/` | 扩展对象（BusCenterExObj） |
| `core/frame/small/` | 小系统服务端 Stub |

## 设计约束与规则

| 规则 | 说明 |
|------|------|
| IPC 序列化 | 所有跨进程调用参数需序列化/反序列化 |
| 系统类型适配 | 三种系统各有独立 IPC 实现，编译配置选择 |
| 插件延迟加载 | BusCenterExObj 通过 dlopen 延迟加载插件 |
| 线程安全 | 插件加载使用 mutex 保护 |
| IPC 回调通道 | Core → SDK 通知通过独立回调通道 |
| 包名鉴权 | SDK 调用需传入 pkgName 进行权限校验 |
| Proxy/Stub 模式 | 扩展对象使用标准 IRemoteProxy/IRemoteStub 模式 |
