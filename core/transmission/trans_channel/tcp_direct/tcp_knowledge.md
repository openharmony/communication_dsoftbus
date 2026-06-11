# TCP通道知识库

## 代码组织

```
core/transmission/trans_channel/tcp_direct/
├─ trans_tcp_direct_manager.c           # TCP通道管理、监听
├─ trans_tcp_direct_manager.c.h
├─ trans_tcp_direct_message.c           # 消息序列化、反序列化
├─ trans_tcp_direct_session.c           # 会话状态管理
└─ trans_tcp_direct_utils.c             # 工具函数

sdk/transmission/trans_channel/tcp_direct/
├─ client_trans_tcp_direct_manager.c    # 客户端TCP发送接收
├─ client_trans_tcp_direct_manager.c.h
└─ client_trans_tcp_direct_stream.c     # 流数据处理
```

## 通道创建流程

```
TransSelectLinkType() → 选择TCP通道
  ↓
TransGetLaneInfo() → 获取WiFi P2P链路信息
  ↓
TransOpenTcpDirectChannel()
  ├─ 建立WiFi P2P连接（如果需要）
  │   ├─ GO/GC角色协商
  │   └─ 分配IP地址
  ├─ 创建TCP socket
  ├─ connect()到对端P2P IP
  └─ OnSessionOpened
```

## TCP消息格式

```c
typedef struct {
    int32_t magic;      // 魔数校验
    int32_t sessionId;  // 会话ID
    int32_t dataLen;    // 数据长度
    int32_t seq;        // 序列号，递增
    int32_t flags;      // 标志位
} TcpMessageHeader;
```

粘包处理定位：`trans_tcp_direct_message.c` 消息解析函数。

## 数据发送流程

```
SendBytes(sessionId, data, len)
  ↓
ClientGetChannelBySessionId() → channelType=TCP
  ↓
client_trans_tcp_direct_manager.c
  ├─ 序列化消息头（TcpMessageHeader）
  ├─ send(fd, header, sizeof(header))
  └─ send(fd, data, len)
```

## 适用数据类型

| SessionType | 传输策略 |
|-------------|---------|
| TYPE_MESSAGE | 单次发送、快速响应 |
| TYPE_BYTES | 顺序保证、完整传输 |
| TYPE_FILE | 分片发送、顺序保证 |

## 连接状态机

```
IDLE → CONNECTING → CONNECTED → DISCONNECTING → IDLE

状态转换规则：
- IDLE → CONNECTING:      OpenSession/Bind调用
- CONNECTING → CONNECTED:  P2P建立+TCP连接成功
- CONNECTED → DISCONNECTING: CloseSession/Shutdown
- 任意 → IDLE:            错误/异常断开
```
