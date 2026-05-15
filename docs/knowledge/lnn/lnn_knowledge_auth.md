# 认证模块 (Authentication)

## 概述

认证模块负责分布式设备间的身份验证和安全通道建立。在设备入网（JoinLNN）流程中，认证是必须的前置步骤——只有通过认证的设备才能进入后续的拓扑同步和节点上线阶段。模块支持多种认证模式以适配不同场景，包括标准 HiChain 设备认证、Identity Service V2 凭据认证和 Meta 认证。

**定位**：组网流程的安全基石，位于 Connection FSM 的 AuthResult 阶段。

## 核心功能

- **设备认证**：通过 4 状态 FSM（SYNC_NEGOTIATION → SYNC_DEVICE_ID → DEVICE_AUTH → SYNC_DEVICE_INFO）完成设备间身份验证
- **HiChain 认证**：标准设备认证协议，支持 V1（设备认证）和 V2（Identity Service）两种模式
- **Identity Service V2 认证**：支持同账号（ACCOUNT_RELATED）、不同账号（ACCOUNT_UNRELATED）、共享凭据（ACCOUNT_SHARED）三种凭据类型
- **快速认证**：已知设备可通过快速认证路径跳过部分步骤
- **会话密钥管理**：协商后的密钥按 LRU 策略管理
- **密钥轮换**：周期性自动轮换会话密钥
- **密钥归一化**：根据设备能力选择不同的密钥处理策略（NOT_SUPPORT / KEY_ERROR / SUPPORT）
- **Meta 认证**：应用级别的认证，生命周期绑定应用进程
- **数据加解密**：基于会话密钥的加密/解密服务，供传输模块调用

## 架构分层

| 层次 | 组件 | 职责 |
|------|------|------|
| 接口层 | auth_interface | 对外暴露认证启动、数据处理、加解密等接口 |
| 会话管理层 | auth_session_fsm | 4 状态 FSM 驱动认证流程 |
| 认证协议层 | auth_hichain + auth_identity_service_adapter | 对接 HiChain 框架和 Identity Service |
| 密钥管理层 | auth_session_key + auth_uk_manager | 会话密钥的存储、轮换和设备密钥管理 |
| 设备管理层 | auth_manager + auth_device | 管理已认证设备、提供加解密操作 |
| 连接层 | auth_connection | 管理认证用的底层连接 |

**依赖**：HiChain 框架、Identity Service、Connection 模块

**被依赖**：Net Builder（JoinLNN 流程调用认证）、Transmission（使用加解密服务）

## 对外接口

| 接口类别 | 说明 |
|---------|------|
| 认证会话控制 | 启动/处理/完成认证会话，驱动 FSM 状态推进 |
| 设备级操作 | 管理已认证设备的连接状态，提供加解密和传输服务 |
| HiChain 交互 | 启动和处理 HiChain 认证数据交换 |
| 会话密钥管理 | 密钥的添加、查询、轮换调度 |
| Meta 认证 | 应用级别的独立认证路径 |
| 认证管理器 | AuthManager 实例的创建、查询、销毁 |

## 代码位置

| 目录 | 说明 |
|------|------|
| `core/authentication/interface/` | 对外接口定义 |
| `core/authentication/include/` | 核心头文件（各子模块接口） |
| `core/authentication/src/` | 实现文件 |
| `core/authentication/manager/` | 认证初始化入口 |
| `core/authentication/accountgroup/` | 账号组管理 |
| `core/authentication/applykey/` | Apply Key 管理 |
| `core/authentication/bind/` | 绑定操作 |
| `core/authentication/userkey/` | 用户密钥管理 |

## 设计约束与规则

| 规则 | 说明 |
|------|------|
| 认证超时 | 每个 FSM 状态有超时上限 |
| 重试机制 | 注册数据重试 3 次/300ms，通用操作重试 5 次 |
| 最大会话密钥数 | 每设备上限，LRU 策略淘汰 |
| 密钥轮换周期 | 自动轮换间隔 |
| 密钥有效期 | 最后使用后的有效期 |
| 线程安全 | AuthManager 操作需加锁 |
| HiChain 回调 | 回调在独立线程上下文执行 |
| 异步通知 | 事件通知使用异步回调避免阻塞 |
