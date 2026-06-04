# Proxy通道知识库

## 代码组织

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

## 通道创建流程

```
TransSelectLinkType() → 选择Proxy（蓝牙链路或受限环境）
  ↓
TransGetLaneInfo() → 获取蓝牙链路信息
  ↓
TransOpenProxyChannel()
  ├─ 向服务端注册Proxy通道
  ├─ 服务端分配Proxy channelId
  └─ 等待对端连接 → OnSessionOpened
```

## 数据转发链路

所有数据必须经过服务端中继转发：

```
客户端A发送:
  SendBytes(sessionId, data, len)
    ↓
  client_trans_proxy_manager.c → ServerIpcSendProxyData() → IPC到服务端

服务端转发:
  softbus_server_stub.cpp → TransSendProxyData()
    ↓
  softbus_proxychannel_manager.c
    ├─ 根据channelId查找对端客户端
    └─ 转发数据到对端

对端客户端接收:
  trans_client_proxy.cpp → ClientOnBytesReceived() → 回调OnBytesReceived
```

关键约束：对端必须在线才能转发成功；服务端维护 Proxy 通道映射表。

## Proxy消息格式

```c
typedef struct {
    int32_t sessionId;    // 会话ID，标识数据归属
    int32_t channelId;    // Proxy通道ID（服务端分配），标识转发路径
    int32_t dataLen;
    int32_t seq;          // 序列号，递增
    int32_t flags;
} ProxyMessageHeader;
```

channelId 由服务端分配标识转发路径；sessionId 用于对端识别数据来源。

## 蓝牙链路类型

| LinkType | 值 | 适用场景 |
|----------|-----|---------|
| LINK_TYPE_BR | 4 | 大数据传输 |
| LINK_TYPE_BLE | 5 | 小数据传输 |
| LINK_TYPE_COC | 8 | 持续传输 |

## 适用数据类型

| SessionType | Proxy策略 |
|-------------|-----------|
| TYPE_MESSAGE | 单次转发 |
| TYPE_BYTES | 服务端转发 |

**约束**：TYPE_FILE / TYPE_STREAM 不适合 Proxy 通道（延迟高），应使用 UDP/TCP。Proxy 通道无重传机制，依赖服务端转发可靠性。检查 `softbus_proxychannel_manager.c::TransOpenProxyChannel()` 定位通道数量限制问题。
