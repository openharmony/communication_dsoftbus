# 通道管理知识库

## 1. 模块功能

通道管理模块负责传输通道的选择和管理：

- **通道选择**：根据需求选择最优传输通道
- **链路管理**：管理各种物理链路（WiFi/蓝牙）
- **通道生命周期**：创建、销毁、状态管理
- **选路策略**：根据数据类型、链路质量选择最优路径

## 2. 模块代码组织结构

```
core/transmission/trans_channel/manager/
├─ trans_channel_manager.c              # 通道管理核心
│                                        # - 通道创建/关闭
│                                        # - 通道状态管理
│                                        # - 通道信息查询
├─ trans_lane_manager.c                 # 链路选择核心
│                                        # - 链路类型选择
│                                        # - 链路质量评估
│                                        # - Lane信息获取
├─ trans_auth_negotiation.c             # 认证协商
│                                        # - Auth通道协商
│                                        # - 认证密钥管理
└─ trans_channel_manager.c.h            # 内部头文件
```

## 3. 模块设计约束及规则

### 四种传输通道

| 通道 | 目录 | 功能 | 适用场景 |
|------|------|------|----------|
| UDP | udp_negotiation | QoS保障、高带宽 | 流数据、大文件 |
| TCP | tcp_direct | WiFi P2P直连、可靠 | 消息、小文件 |
| Proxy | proxy | 服务端中继转发 | 蓝牙、受限环境 |
| Auth | auth | 加密传输 | 认证阶段、安全传输 |

### 选路流程

```
OpenSession/Bind请求
  ↓
TransSelectLinkType()  [trans_lane_manager.c]
  ├─ 解析SessionAttribute
  ├─ 获取linkType[]（用户指定）
  ├─ 查询LNN获取可用链路
  └─ 评估链路质量
  ↓
TransGetLaneInfo()
  ├─ 根据选定的linkType
  ├─ 查询链路详细信息
  └─ 返回LaneInfo
  ↓
TransOpenChannel()  [trans_channel_manager.c]
  ├─ 根据channelType创建通道
  ├─ UDP: TransOpenUdpChannel()
  ├─ TCP: TransOpenTcpDirectChannel()
  ├─ Proxy: TransOpenProxyChannel()
  ├─ Auth: TransOpenAuthChannel()
  └─ 返回TransInfo（channelId, channelType）
```

### 选路策略规则

**优先级（从高到低）**：

1. **用户指定**：
   - SessionAttribute.linkType[] 明确指定
   - 直接使用指定链路类型

2. **数据类型自动选择**：
   ```
   TYPE_STREAM  → UDP通道（低延迟、高带宽）
   TYPE_FILE    → UDP/TCP通道（高带宽）
   TYPE_MESSAGE → TCP通道（可靠、低延迟）
   TYPE_BYTES   → 根据链路质量选择
   TYPE_D2D_MESSAGE → Auth通道（加密）
   ```

3. **链路可用性**：
   ```
   WiFi可用 → 优先TCP/UDP
   蓝牙可用 → 使用Proxy
   受限环境 → 使用Proxy
   ```

4. **链路质量评估**：
   - 带宽：选择带宽最高的链路
   - 延迟：选择延迟最低的链路
   - 稳定性：选择最稳定的链路

### LinkType链路类型规则

| LinkType | 值 | 适用通道 | 特点 |
|----------|-----|----------|------|
| LINK_TYPE_WIFI_WLAN_5G | 1 | UDP, TCP | 5G WiFi，高带宽 |
| LINK_TYPE_WIFI_WLAN_2G | 2 | UDP, TCP | 2.4G WiFi，覆盖广 |
| LINK_TYPE_WIFI_P2P | 3 | TCP (优先) | P2P直连，低延迟 |
| LINK_TYPE_BR | 4 | Proxy | 传统蓝牙，速率较高 |
| LINK_TYPE_BLE | 5 | Proxy | 低功耗蓝牙 |
| LINK_TYPE_BLE_DIRECT | 7 | Auth | BLE直连 |
| LINK_TYPE_COC | 8 | Proxy | 蓝牙面向连接 |
| LINK_TYPE_HML | 10 | TCP, UDP | HML链路 |
| LINK_TYPE_SLE | 11 | TCP, UDP | SLE链路 |

### 通道管理接口

```c
// 创建通道
int32_t TransOpenChannel(
    const SessionParam *param,    // 会话参数（sessionName、dataType、linkType）
    const LaneInfo *laneInfo,     // 链路信息
    TransInfo *transInfo          // 输出：channelId、channelType
);

// 关闭通道
int32_t TransCloseChannel(
    int32_t channelId,            // 通道ID
    int32_t channelType           // 通道类型
);

// 查询通道信息
int32_t TransGetChannelInfo(
    int32_t channelId,
    int32_t channelType,
    ChannelInfo *info             // 输出：通道详细信息
);
```

### Auth通道规则

**功能**：加密传输，认证阶段使用

**创建流程**：
```
设备认证 → 获取authId → TransOpenAuthChannel() → 加密通道
```

**适用场景**：
- TYPE_D2D_MESSAGE：设备间加密消息
- 认证阶段的安全传输

### 通道数量限制规则

**限制约束**：
- 每种通道类型有最大数量限制
- 超过限制时TransOpenChannel()返回失败
- 需及时关闭不用的通道释放资源

### 链路切换规则

**切换场景**：
- 当前链路质量下降
- 新链路可用且质量更好
- 用户请求切换链路

**切换流程**：
```
1. 检查新链路可用性
2. 创建新通道
3. 迁移数据传输到新通道
4. 关闭旧通道
```

**约束**：
- 切换时需缓存未发送数据
- 切换成功后继续传输
- 切换失败保持原通道

### 最佳实践

```c
// 大文件传输：指定5G WiFi
SessionAttribute attr;
attr.dataType = TYPE_FILE;
attr.linkType[0] = LINK_TYPE_WIFI_WLAN_5G;

// 实时音视频：指定P2P直连
attr.dataType = TYPE_STREAM;
attr.linkType[0] = LINK_TYPE_WIFI_P2P;

// 蓝牙环境：指定BLE
attr.dataType = TYPE_MESSAGE;
attr.linkType[0] = LINK_TYPE_BLE;

// QoS参数设置
QosTV qos[2];
qos[0].type = QOS_TYPE_MIN_BW;
qos[0].value = 1000;     // 1000 kbps最小带宽
qos[1].type = QOS_TYPE_MAX_LATENCY;
qos[1].value = 100;      // 100ms最大延迟
SetSessionAttribute(session, &attr, qos, 2);
```

### 问题定位

| 问题 | 定位文件 | 关键函数 |
|------|----------|----------|
| 通道选择错误 | `trans_lane_manager.c` | `TransSelectLinkType()` |
| 无可用链路 | `trans_lane_manager.c` | `TransGetLaneInfo()` |
| 通道创建失败 | `trans_channel_manager.c` | `TransOpenChannel()` |
| 通道资源不足 | `trans_channel_manager.c` | 通道数量限制检查 |
| 链路切换失败 | `trans_lane_manager.c` | 链路质量评估 |