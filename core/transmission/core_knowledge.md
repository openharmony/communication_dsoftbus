# 传输核心架构知识库

## 1. 模块功能

提供跨设备数据传输能力，核心架构：

```
用户应用
  ↓ session.h / socket.h
SDK层 (sdk/transmission)
  ↓ IPC Binder
服务端SA (core/frame/softbus_server)
  ↓
核心传输 (core/transmission)
  ↓
连接层 (core/connection)
  ↓
物理链路 (WiFi/BLE/BR/SLE)
```

**核心能力**：
- 两套接口：Session (异步) / Socket (同步)
- 四种通道：UDP / TCP / Proxy / Auth
- IPC通信：客户端 ↔ 服务端
- 权限检查：UID/PID/AccessToken/安全级别

## 2. 模块代码组织结构

```
sdk/transmission/
├─ session/src/
│   ├─ client_trans_session_service.c    # 用户接口入口
│   ├─ client_trans_session_manager.c    # 会话状态管理
│   └─ client_trans_session_callback.c   # 回调处理
├─ trans_channel/                         # 通道客户端实现
│   ├─ udp/common/src/client_trans_udp_manager.c
│   ├─ tcp_direct/src/client_trans_tcp_direct_manager.c
│   └─ proxy/src/client_trans_proxy_manager.c
└─ ipc/standard/src/
    ├─ trans_server_proxy.cpp             # 客户端→服务端IPC
    └─ trans_server_proxy_standard.cpp

core/transmission/
├─ session/src/
│   ├─ trans_session_manager.c           # 服务端会话管理
│   └─ trans_session_service.c           # 会话服务
├─ trans_channel/
│   ├─ manager/
│   │   ├─ trans_channel_manager.c       # 通道创建/关闭
│   │   ├─ trans_lane_manager.c          # 链路选择
│   │   └─ trans_auth_negotiation.c      # 认证协商
│   ├─ udp_negotiation/                  # UDP通道
│   ├─ tcp_direct/                       # TCP直连
│   ├─ proxy/                            # Proxy中继
│   └─ auth/                             # Auth加密
└─ ipc/standard/src/
    └─ trans_client_proxy.cpp            # 服务端→客户端IPC

core/frame/standard/init/src/
├─ softbus_server.cpp                    # SA主程序
├─ softbus_server_stub.cpp               # IPC处理（权限检查核心）
└─ if_softbus_server.cpp                 # 接口定义
```

## 3. 模块设计约束及规则

### 接口约束

**Session接口 (v1.0)** - RPC风格，异步连接：

| 接口 | 流程 |
|------|------|
| CreateSessionServer | SDK注册 → IPC → SA记录 |
| OpenSession | 分配sessionId → IPC → SA选路建通道 → 回调OnSessionOpened |
| SendBytes | 根据channelType调用对应通道 |
| CloseSession | 关通道 → IPC通知SA → 回调OnSessionClosed |

**Socket接口 (v2.0)** - Socket风格，同步连接：

| 接口 | 流程 |
|------|------|
| ServiceSocket | 内部调用CreateSessionServer |
| Socket | 返回socket fd |
| Bind | 内部调用OpenSession，阻塞等OnBind |
| SendBytesAsync | 支持OnBytesSent确认 |
| Shutdown | 内部调用CloseSession |

**关键约束**：`socket FD == sessionId`，两套接口共享底层通道

### IPC通信规则

```cpp
// 客户端→服务端请求码
CREATE_SESSION_SERVER = 1
REMOVE_SESSION_SERVER = 2
OPEN_SESSION = 3
CLOSE_CHANNEL = 4
SEND_PROXY_DATA = 5

// 服务端→客户端回调
CLIENT_ON_BYTES_RECEIVED
CLIENT_ON_SESSION_OPENED
CLIENT_ON_SESSION_CLOSED
```

### 权限检查规则

`softbus_server_stub.cpp::CheckOpenSessionPermission()` 检查：

1. **CheckTransPermission**：UID/PID/AccessToken匹配
2. **CheckUidAndPid**：sessionName与pkgName匹配
3. **CheckTransSecLevel**：安全级别一致性

### 数据类型约束

| SessionType | 值 | 适用通道 | 特点 |
|-------------|-----|----------|------|
| TYPE_MESSAGE | 1 | TCP/Proxy | 小数据、可靠 |
| TYPE_BYTES | 2 | 全部 | 通用字节流 |
| TYPE_FILE | 3 | UDP/TCP | 大数据传输 |
| TYPE_STREAM | 4 | UDP | 实时音视频 |
| TYPE_D2D_MESSAGE | 10 | Auth | 设备间消息 |

### 调用流程约束

```
SDK: client_trans_session_service.c
  ├─ 参数校验
  ├─ ClientAddSession() → 分配sessionId
  └─ ServerIpcOpenSession() → IPC

SA: softbus_server_stub.cpp
  ├─ CheckOpenSessionPermission()
  └─ TransOpenSession()

Core: trans_channel_manager.c
  ├─ TransSelectLinkType()
  ├─ TransGetLaneInfo()
  └─ TransOpenChannel() → UDP/TCP/Proxy/Auth
```