# OpenHarmony软总线传输模块 - 知识库索引

## 知识库列表

| 知识库 | 路径 | 内容 | 加载场景 |
|--------|------|------|----------|
| core_knowledge.md | ./core_knowledge.md | 整体架构、接口、IPC、权限 | 理解模块整体设计 |
| udp_knowledge.md | ./trans_channel/udp_negotiation/udp_knowledge.md | UDP通道、QoS机制 | UDP传输问题、流数据、大文件 |
| tcp_knowledge.md | ./trans_channel/tcp_direct/tcp_knowledge.md | TCP通道、WiFi P2P | TCP连接问题、消息传输 |
| proxy_knowledge.md | ./trans_channel/proxy/proxy_knowledge.md | Proxy通道、蓝牙链路 | Proxy转发问题、蓝牙传输 |
| manager_knowledge.md | ./trans_channel/manager/manager_knowledge.md | 通道选择、链路管理 | 选路问题、链路切换 |

## 问题定位指南

| 问题 | 定位文件 |
|------|----------|
| OpenSession失败 | `softbus_server_stub.cpp::CheckOpenSessionPermission()` |
| IPC问题 | `trans_server_proxy.cpp` / `trans_client_proxy.cpp` |
| 回调未触发 | `client_trans_session_callback.c` |
| UDP问题 | `trans_udp_negotiation.c` |
| TCP问题 | `trans_tcp_direct_manager.c` |
| Proxy问题 | `softbus_proxychannel_manager.c` |
| 选路问题 | `trans_lane_manager.c` |

## 模块概览

### 功能
提供跨设备数据传输能力，两套接口、四种通道

### 接口对比

| 接口 | 连接方式 | 适用场景 |
|------|----------|----------|
| Session (v1.0) | OpenSession (异步) | 简单场景 |
| Socket (v2.0) | Bind (同步阻塞) | 需同步等待 |

### 四种通道

| 通道 | 场景 | 特点 |
|------|------|------|
| UDP | 流/大文件 | QoS、高带宽 |
| TCP | 消息/小文件 | WiFi P2P、可靠 |
| Proxy | 蓝牙/受限 | 服务端中继 |
| Auth | 认证阶段 | 加密传输 |

## 快速选择知识库

```
整体架构理解      → ./core_knowledge.md
UDP传输问题       → ./trans_channel/udp_negotiation/udp_knowledge.md
TCP连接问题       → ./trans_channel/tcp_direct/tcp_knowledge.md
蓝牙/Proxy问题    → ./trans_channel/proxy/proxy_knowledge.md
选路问题          → ./trans_channel/manager/manager_knowledge.md
```