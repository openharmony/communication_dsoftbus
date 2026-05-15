# WiFi Direct 连接模块知识

## 模块基础功能

### P2P 实体管理

```cpp
class P2pEntity {
public:
    static P2pEntity *GetInstance();  // 单例模式
    int32_t CreateGroup(const Config &config);  // GO 模式
    int32_t Connect(const Config &config, const std::string &pin);  // GC 模式
    int32_t Disconnect();
    int32_t RemoveGroup();
};
```

### 链路角色

```cpp
enum class P2pRole {
    GO = 0,  // Group Owner（类似 AP）
    GC = 1,  // Group Client
};

enum class LinkState {
    DISABLED, CONNECTING, CONNECTED, DISCONNECTING
};
```

---

## 模块组织架构

### 目录结构

```
core/connection/wifi_direct_cpp/
├── include/
│   ├── wifi_direct_p2p_entity.h
│   ├── wifi_direct_manager.h
│   └── wifi_direct_config.h
└── src/
    ├── wifi_direct_p2p_entity.cpp
    ├── wifi_direct_manager.cpp
    └── wifi_direct_config.cpp
```

### 架构关系

```
┌──────────────────────────────┐
│    上层连接管理接口           │
└────────────┬─────────────────┘
             │
┌────────────▼─────────────────┐
│     P2pEntity（单例）         │
│  - CreateGroup（GO 模式）     │
│  - Connect（GC 模式）         │
└────────────┬─────────────────┘
             │
┌────────────▼─────────────────┐
│    WiFi Direct HAL 层        │
└──────────────────────────────┘
```

---

## 模块设计约束及规则

### 单例约束

**规则**：整个 WiFi Direct 只有一个 P2P 实体实例，同时只能有一个组

```cpp
P2pEntity *p2p = P2pEntity::GetInstance();

// 错误：同时创建多个组
p2p->CreateGroup(config1);
p2p->CreateGroup(config2);  // 失败或覆盖

// 正确：先移除再创建
p2p->RemoveGroup();
p2p->CreateGroup(config2);
```

### GO/GC 角色约束

**规则**：设备必须选择 GO 或 GC 角色之一

```cpp
// 作为 GO（创建组）
WifiDirectConfig config;
config.channel = 6;
config.goSize = 10;
p2p->CreateGroup(config);  // 等待其他设备连接

// 作为 GC（连接到组）
WifiDirectConfig config;
config.goMac = "AA:BB:CC:DD:EE:FF";
config.pin = "12345678";
p2p->Connect(config, "12345678");  // 连接到 GO
```

### 连接状态约束

**规则**：必须检查连接状态后再进行操作

```cpp
if (p2p->GetLinkState() == LinkState::CONNECTED) {
    // 已连接，执行数据传输
}
```

---

**关键文件**：
- `core/connection/wifi_direct_cpp/include/wifi_direct_p2p_entity.h` - P2P 实体接口

---

**文档版本**：v2.0 | **更新**：2026-05-15
