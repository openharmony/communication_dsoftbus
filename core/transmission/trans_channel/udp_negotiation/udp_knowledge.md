# UDP通道知识库

## 1. 模块功能

UDP通道提供高带宽、低延迟传输能力，适用场景：

- **流数据传输**：实时音视频，低延迟优先
- **大文件传输**：高速数据传输，带宽优先
- **QoS保障**：带宽评估、重传机制、优先级队列

## 2. 模块代码组织结构

```
core/transmission/trans_channel/udp_negotiation/
├─ trans_udp_negotiation.c              # UDP通道创建、协商、管理
├─ trans_udp_negotiation.c.h            # 内部头文件
├─ trans_udp_negotiation_stream.c       # 流数据QoS处理
└─ trans_udp_negotiation_utils.c        # 工具函数

sdk/transmission/trans_channel/udp/
├─ client_trans_udp_manager.c           # 客户端UDP管理
├─ client_trans_udp_manager.c.h
└─ client_trans_udp_stream.c            # 流数据客户端
```

## 3. 模块设计约束及规则

### 通道创建流程

```
TransSelectLinkType() → 选择UDP通道
  ↓
TransGetLaneInfo() → 获取UDP链路信息
  ↓
TransOpenUdpChannel()
  ├─ 创建UDP socket
  ├─ 发送协商请求到对端
  └─ 等待对端响应 → OnSessionOpened
```

### QoS机制约束

**带宽评估规则**：
- TYPE_STREAM：高带宽优先，动态调整
- TYPE_FILE：稳定带宽，重传保障
- TYPE_BYTES：普通带宽

**重传机制规则**：
- 序列号追踪：每个数据包分配seq
- ACK确认：对端收到后回复ACK
- 超时重传：超时未收到ACK则重传
- 丢包检测：检测丢包并触发重传

**优先级队列规则**：
```c
HIGH_PRIORITY:   控制消息，优先发送
NORMAL_PRIORITY: 普通数据，正常队列
LOW_PRIORITY:    后台传输，低优先级
```

### 数据发送流程

```
SendBytes(sessionId, data, len)
  ↓
ClientGetChannelBySessionId() → channelType=UDP
  ↓
client_trans_udp_manager.c
  ├─ 获取UDP socket fd
  ├─ 应用QoS策略
  │   ├─ 带宽评估
  │   ├─ 优先级队列选择
  │   └─ 重传控制
  └─ sendto(fd, data, len, ...)
```

### 适用数据类型约束

| SessionType | UDP特点 | QoS策略 |
|-------------|---------|---------|
| TYPE_FILE | 高带宽、重传保障 | 稳定带宽、完整重传 |
| TYPE_STREAM | 低延迟、丢包容忍 | 高带宽、部分丢包容忍 |
| TYPE_BYTES | 普通传输 | 普通带宽 |

### 性能约束

- **MTU限制**：UDP有MTU限制，大数据需分片
- **缓冲区管理**：合理设置发送/接收缓冲区
- **带宽限制**：根据网络状况动态调整发送速率

### 可靠性约束

UDP通道可靠性可选：
- 启用重传：高可靠场景
- 禁用重传：实时场景（丢包容忍）

### 与其他通道对比

| 特性 | UDP | TCP |
|------|-----|-----|
| 延迟 | 低 | 中 |
| 带宽 | 高 | 中 |
| 可靠性 | 可选 | 高 |
| 适用场景 | 流/文件 | 消息/小文件 |