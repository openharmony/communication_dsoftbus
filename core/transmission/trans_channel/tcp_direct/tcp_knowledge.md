# TCP通道知识库

## 1. 模块功能

TCP通道提供可靠、低延迟传输能力，适用场景：

- **消息传输**：小数据、控制消息，可靠性优先
- **小文件传输**：稳定传输，顺序保证
- **WiFi P2P直连**：点对点通信，低延迟

## 2. 模块代码组织结构

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

## 3. 模块设计约束及规则

### 通道创建流程

```
TransSelectLinkType() → 选择TCP通道
  ↓
TransGetLaneInfo() → 获取WiFi P2P链路信息
  ↓
TransOpenTcpDirectChannel()
  ├─ 建立WiFi P2P连接（如果需要）
  │   ├─ 设备发现
  │   ├─ GO/GC角色协商
  │   ├─ 分配IP地址
  │   └─ 建立P2P连接
  ├─ 创建TCP socket
  ├─ connect()到对端P2P IP
  └─ OnSessionOpened
```

### WiFi P2P直连规则

**P2P建立流程**：
```
1. 设备发现：LNN发现对端，确认支持WiFi P2P
2. P2P协商：创建Group，协商GO/GC角色
3. IP分配：P2P Group分配IP地址
4. TCP连接：获取对端IP，建立TCP连接
```

**P2P优势**：
- 直连传输：不经过路由器
- 低延迟：点对点通信
- 高带宽：WiFi速率
- 稳定可靠：TCP保障

### TCP消息格式约束

```c
typedef struct {
    int32_t magic;      // 魔数校验，固定值
    int32_t sessionId;  // 会话ID
    int32_t dataLen;    // 数据长度
    int32_t seq;        // 序列号，递增
    int32_t flags;      // 标志位
} TcpMessageHeader;
```

**约束**：
- magic固定值用于校验消息有效性
- seq递增用于消息顺序追踪
- dataLen必须与实际数据长度一致

### 数据发送流程

```
SendBytes(sessionId, data, len)
  ↓
ClientGetChannelBySessionId() → channelType=TCP
  ↓
client_trans_tcp_direct_manager.c
  ├─ 获取TCP socket fd
  ├─ 序列化消息头（TcpMessageHeader）
  ├─ send(fd, header, sizeof(header))
  └─ send(fd, data, len)
```

### 适用数据类型约束

| SessionType | TCP特点 | 传输策略 |
|-------------|---------|---------|
| TYPE_MESSAGE | 小数据、低延迟 | 单次发送、快速响应 |
| TYPE_BYTES | 可靠传输 | 顺序保证、完整传输 |
| TYPE_FILE | 顺序传输 | 分片发送、顺序保证 |

### TCP连接约束

**连接状态**：
```
IDLE → CONNECTING → CONNECTED → DISCONNECTING → IDLE

状态转换规则：
- IDLE → CONNECTING: OpenSession/Bind调用
- CONNECTING → CONNECTED: P2P建立+TCP连接成功
- CONNECTED → DISCONNECTING: CloseSession/Shutdown
- 任意 → IDLE: 错误/异常断开
```

### 粘包处理约束

TCP粘包问题：
- 应用层必须解析消息头
- 根据dataLen读取完整数据
- 定位：`trans_tcp_direct_message.c` 消息解析

### 性能优化规则

```c
// 推荐设置
TCP_NODELAY: 减少延迟，禁用Nagle算法
TCP_QUICKACK: 快速ACK
SO_SNDBUF/SO_RCVBUF: 调整缓冲区大小
TCP_KEEPALIVE: 保持连接活跃
```

### 与其他通道对比

| 特性 | TCP | UDP |
|------|-----|-----|
| 延迟 | 低(P2P) | 最低 |
| 可靠性 | 最高 | 可选 |
| 带宽 | 高 | 最高 |
| 适用场景 | 消息/小文件 | 流/大文件 |