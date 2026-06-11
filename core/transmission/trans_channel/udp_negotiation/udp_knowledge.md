# UDP通道知识库

## 代码组织

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

## 通道创建流程

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

## 数据发送流程

```
SendBytes(sessionId, data, len)
  ↓
ClientGetChannelBySessionId() → channelType=UDP
  ↓
client_trans_udp_manager.c
  ├─ 获取UDP socket fd
  └─ sendto(fd, data, len, ...)
```

## 适用数据类型

| SessionType | QoS策略 |
|-------------|---------|
| TYPE_FILE | 稳定带宽、完整重传 |
| TYPE_STREAM | 高带宽、丢包容忍 |
| TYPE_BYTES | 普通带宽 |

## 可靠性约束

UDP通道可靠性可选：
- 启用重传：高可靠场景（TYPE_FILE）
- 禁用重传：实时场景（TYPE_STREAM，丢包容忍）
