# WiFi Direct 连接模块知识

## 核心功能

基于 P2P 实体（单例）管理 WiFi Direct 连接，支持 GO（Group Owner）和 GC（Group Client）两种角色，提供组的创建、连接、断开、移除能力。

关键 API：
- `P2pEntity::GetInstance()` — 获取单例实例
- `P2pEntity::CreateGroup()` — GO 模式创建组
- `P2pEntity::Connect()` — GC 模式连接到组
- `P2pEntity::RemoveGroup()` — 移除当前组

## 代码地图

```
core/connection/wifi_direct_cpp/
├── include/
│   ├── wifi_direct_p2p_entity.h   # P2P 实体接口（单例）
│   ├── wifi_direct_manager.h      # WiFi Direct 管理器
│   └── wifi_direct_config.h       # 配置定义
└── src/
    ├── wifi_direct_p2p_entity.cpp # P2P 实体实现
    ├── wifi_direct_manager.cpp    # 管理器实现
    └── wifi_direct_config.cpp     # 配置实现
```

架构分层：上层连接管理接口 → P2pEntity（单例） → WiFi Direct HAL 层

## 设计约束与规则

- **单例约束**：P2P 实体是单例，同时只能有一个组；建链时如果已有组，则进行复用;
- **GO/GC 角色**：设备必须选择 GO（创建组）或 GC（连接到组）角色之一，不可兼具

## 基本术语

| 术语 | 说明 |
|------|------|
| P2pEntity | WiFi Direct P2P 实体，单例模式，管理组生命周期 |
| LinkState | 连接状态枚举：DISABLED / CONNECTING / CONNECTED / DISCONNECTING |
| WifiDirectConfig | 连接配置结构体，含 channel、goMac、pin 等参数 |
