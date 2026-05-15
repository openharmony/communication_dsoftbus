# Proxy通道知识库

## 1. 模块功能

Proxy通道提供服务端中继转发能力，适用场景：

- **蓝牙环境**：BR/BLE/CoC链路传输
- **受限环境**：无法建立P2P直连
- **服务端中继**：所有数据经过服务端转发

**核心特点**：
- 不需要客户端间直接连接
- 服务端作为中继节点转发数据
- 支持多种蓝牙链路类型

## 2. 模块代码组织结构

```
core/transmission/trans_channel/proxy/
├─ softbus_proxychannel_manager.c       # Proxy通道管理、转发核心
├─ softbus_proxychannel_manager.c.h
├─ softbus_proxychannel_message.c       # 消息序列化、转发逻辑
├─ softbus_proxychannel_session.c       # Proxy会话状态管理
└─ softbus_proxychannel_utils.c         # 工具函数

sdk/transmission/trans_channel/proxy/
├─ client_trans_proxy_manager.c         # 客户端Proxy发送
├─ client_trans_proxy_manager.c.h
└─ client_trans_proxy_stream.c          # 流数据客户端

core/frame/standard/init/src/
└─ softbus_server_stub.cpp              # IPC接收Proxy数据请求
```

## 3. 模块设计约束及规则

### 通道创建流程

```
TransSelectLinkType() → 选择Proxy（蓝牙链路或受限环境）
  ↓
TransGetLaneInfo() → 获取蓝牙链路信息
  ↓
TransOpenProxyChannel()
  ├─ 向服务端注册Proxy通道
  ├─ 服务端分配Proxy channelId
  ├─ 等待对端连接
  └─ OnSessionOpened
```

### 数据转发流程规则

**完整转发链路**：
```
客户端A发送:
  ↓
SendBytes(sessionId, data, len)
  ↓
client_trans_proxy_manager.c
  ├─ 获取Proxy channelId
  └─ ServerIpcSendProxyData() → IPC到服务端

服务端转发:
  ↓
softbus_server_stub.cpp
  ├─ 接收Proxy数据请求
  └─ TransSendProxyData()

softbus_proxychannel_manager.c
  ├─ 根据channelId查找对端客户端
  ├─ 检查对端是否在线
  └─ 转发数据到对端

对端客户端接收:
  ↓
trans_client_proxy.cpp
  ├─ ClientOnBytesReceived()
  └─ 回调OnBytesReceived
```

**关键约束**：
- 所有数据必须经过服务端转发
- 服务端维护Proxy通道映射表
- 对端必须在线才能转发成功

### Proxy消息格式约束

```c
typedef struct {
    int32_t sessionId;    // 会话ID，标识数据归属
    int32_t channelId;    // Proxy通道ID，标识转发路径
    int32_t dataLen;      // 数据长度
    int32_t seq;          // 序列号，递增
    int32_t flags;        // 标志位
} ProxyMessageHeader;
```

**约束**：
- channelId由服务端分配，标识转发路径
- sessionId用于对端识别数据来源
- seq递增用于消息顺序追踪

### 蓝牙链路支持规则

| LinkType | 值 | 特点 | 适用场景 |
|----------|-----|------|----------|
| LINK_TYPE_BR | 4 | 传统蓝牙，速率较高 | 大数据传输 |
| LINK_TYPE_BLE | 5 | 低功耗蓝牙，速率低 | 小数据传输 |
| LINK_TYPE_COC | 8 | 蓝牙面向连接，速率适中 | 持续传输 |

**选择规则**：
- 大数据优先BR链路
- 低功耗场景BLE链路
- 持续传输CoC链路

### 适用数据类型约束

| SessionType | Proxy特点 | 转发策略 |
|-------------|-----------|---------|
| TYPE_MESSAGE | 小数据、中继转发 | 单次转发、快速响应 |
| TYPE_BYTES | 通用字节流 | 服务端转发 |

**约束**：
- TYPE_FILE/TYPE_STREAM不适合Proxy通道（延迟高）
- 大数据建议使用UDP/TCP通道

### 资源管理约束

**Proxy通道数量限制**：
- 服务端有最大Proxy通道数量限制
- 超过限制时创建失败
- 定位：`softbus_proxychannel_manager.c::TransOpenProxyChannel()`

**通道复用规则**：
- 同一sessionName可复用Proxy通道
- 避免频繁创建/销毁Proxy通道
- 及时关闭不用的Proxy通道

### 性能约束

**延迟约束**：
- Proxy经过服务端中继，延迟较高
- 不适合实时性要求高的场景

**可靠性约束**：
- Proxy通道无重传机制
- 依赖服务端转发可靠性
- 检查服务端转发日志定位丢失原因

### 与其他通道对比

| 特性 | Proxy | TCP | UDP |
|------|-------|-----|-----|
| 延迟 | 高 | 低(P2P) | 最低 |
| 可靠性 | 高（服务端转发） | 最高 | 可选 |
| 带宽 | 低 | 高 | 最高 |
| 适用场景 | 蓝牙/受限 | 消息/小文件 | 流/大文件 |

### 使用场景规则

```c
// 蓝牙环境：明确指定蓝牙链路
attr.dataType = TYPE_MESSAGE;
attr.linkType[0] = LINK_TYPE_BLE;  // 或 LINK_TYPE_BR, LINK_TYPE_COC

// 受限环境：自动选择Proxy（无P2P可用）
attr.dataType = TYPE_MESSAGE;
// 系统自动选择Proxy通道
```