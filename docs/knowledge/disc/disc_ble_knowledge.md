# BLE 设备发现 精练知识库

> 路径：`core/discovery/ble/softbus_ble` | 源码 ~3467 行 | 3 个源文件

---

## 一、模块功能

通过 BLE 广播/扫描实现周边设备的发布与发现。支持 CastPlus、DVKIT、OSD 三种能力，提供主动/被动发布与发现机制。使用 Handler-Looper 消息循环将所有广播/扫描操作序列化到单一线程。

**核心职责**：
- BLE 广播数据组装（TLV 编码：设备哈希/类型/BR MAC/测距/自定义数据）
- BLE 扫描结果解析（TLV 解码、能力匹配、同账号校验、测距）
- 主动发布（NON 广播） / 主动发现（CON 广播 + 扫描）
- 被动发布/被动发现（扫描到对端请求后回复 NON 广播）
- 接收消息超时管理（6 秒自动清理，触发 NON 广播更新）
- 蓝牙状态驱动（BLE 开/关恢复/停止，BR 开/关更新 NON 广播）
- Action 机制（HML PreLink）
- DFX 定时统计上报

**关键 API**：

| API | 说明 |
|-----|------|
| `DiscSoftBusBleInit()` | 初始化：注册广播器(CON/NON) + 扫描监听器 + BT 状态监听 + Looper |
| `BleStartActivePublish()` | 主动发布：注册能力 → PostMessage → 启动 NON 广播 |
| `BleStartActiveDiscovery()` | 主动发现：注册能力 → PostMessage → 启动 CON 广播 + 扫描 |
| `BleScanResultCallback()` | 扫描结果入口：过滤 → 解析 → 连接型/非连接型分发 |
| `DiscBleMsgHandler()` | Looper 消息处理核心（16 种消息类型） |
| `ProcessBleDiscFunc()` | 所有外部接口的统一入口：状态检查 → 能力注册 → PostMessage |

---

## 二、代码组织

```
core/discovery/ble/softbus_ble/
├── include/
│   ├── disc_ble.h           — 初始化/反初始化接口
│   ├── disc_ble_constant.h  — TLV 类型、位置常量（聚合头文件）
│   └── disc_ble_utils.h     — 工具函数声明
└── src/
    ├── disc_ble.c (2754行) — 核心业务：广播/扫描/消息处理/状态管理
    ├── disc_ble_utils.c (489行) — TLV 编解码、设备信息获取、过滤器构建
    └── disc_ble_virtual.c (111行) — 不支持 BLE 平台的桩实现
```

**代码量分布**：核心业务 66% | 编解码工具 18% | 全局变量/宏 10% | 桩实现 3% | 接口 3%

**核心数据结构**：

| 结构体 | 用途 |
|--------|------|
| `DiscBleMessage` (16 种) | 驱动整个消息循环的消息类型枚举 |
| `DiscBleAdvertiser[2]` | CON/NON 两个广播器（含 isAdvertising, isRspDataEmpty 原子变量） |
| `DiscBleInfo[4]` | 4 种模式的能力信息管理（发布/订阅 × 主动/被动） |
| `RecvMessage` | 扫描到的需回复消息（链表节点，含 capBitMap + key 哈希去重） |
| `RecvMessageInfo` | 接收消息链表管理（自带递归锁） |
| `g_discBleHandler` | SoftBusHandler，消息处理器 |

**全局变量保护**：

| 变量 | 保护方式 |
|------|----------|
| `g_bleInfoManager[4]` | `g_bleInfoLock` 互斥锁 |
| `g_recvMessageInfo` | 自带 `lock`（递归锁） |
| `g_bleAdvertiser[].isRspDataEmpty` | `_Atomic bool` |
| `g_isScanning` | 无锁（Looper 线程内） |

---

## 三、架构设计约束与规则

### 设计模式

| 模式 | 说明 | 位置 |
|------|------|------|
| **Handler-Looper** | 所有广播/扫描操作通过 PostMessage 投递到 Looper 线程串行执行，外部接口不直接操作硬件 | disc_ble.c → DiscBleMsgHandler |
| **策略模式** | `DiscoveryFuncInterface` 函数指针结构体向上层暴露统一接口 | disc_ble.c:1914 |
| **引用计数** | `capCount[pos]` 对每个能力位的注册次数计数，减到 0 才清除 | disc_ble.c:1477/1524 |
| **TLV 编解码** | 广播数据用 TLV 格式（高 4 位 Type，低 4 位 Length），递归解析 | disc_ble_utils.c:155/369 |
| **桩实现** | `disc_ble_virtual.c` 所有函数返回 `SOFTBUS_NOT_IMPLEMENT` | disc_ble_virtual.c |

### 线程模型

**三个线程上下文**：
1. **调用线程** — 外部接口（Publish/Discovery）只做参数处理 + PostMessage
2. **Looper 线程** — DiscBleMsgHandler 处理所有广播启停/扫描启停/超时消息
3. **BLE 回调线程** — BleScanResultCallback/BleAdvEnableCallback 等底层回调

**锁列表**（2 把 + 1 原子变量）：

| 锁 | 类型 | 保护对象 | 特殊说明 |
|----|------|----------|----------|
| `g_bleInfoLock` | 互斥锁 | `g_bleInfoManager[4]` 的所有读写 | 持锁时间应尽量短 |
| `g_recvMessageInfo.lock` | 递归锁 | 接收消息链表/计数 | 递归防嵌套死锁 |
| `isRspDataEmpty` | `_Atomic bool` | 响应数据空标记 | 处理 BLE B 包芯片规避 |

**死锁防护**：两把锁不会同时持有。`g_recvMessageInfo.lock` 为递归锁，避免 `AddRecvMessage → ReplyPassiveNonBroadcast → PostMessage` 嵌套死锁。

### 关键约束规则

1. **外部接口只 PostMessage** — 不直接操作广播/扫描硬件，保证状态变更在 Looper 线程串行执行
2. **扫描回调持 g_bleInfoLock** — 但不同时持有 recvMessageInfo.lock
3. **6 秒超时自动清理** — RecvMessage 超时后移除，触发 NON 广播更新
4. **蓝牙开/关驱动** — BLE 开启 → RECOVERY（恢复广播+扫描）；BLE 关闭 → TURN_OFF（停止一切）；BR 变化 → 更新 NON 广播的 BR MAC TLV
5. **能力引用计数** — 同一能力多次注册时 capCount 递增，取消时递减到 0 才真正清除
6. **isRspDataEmpty 原子操作** — 用于 BLE 广播 B 包更新的芯片规避，必须原子读写
7. **CON/NON 双广播器** — CON(连接型) 用于主动发现，NON(非连接型) 用于主动发布和被动回复
8. **扫描结果分流** — 根据 `BIT_CON` 标志位区分连接型/非连接型包，分别走 ProcessDisConPacket/ProcessDisNonPacket

### 关键常量

```c
BLE_VERSION = 4              // 协议版本
NUM_ADVERTISER = 2           // 广播器数量 (CON=0, NON=1)
BLE_INFO_COUNT = 4           // 模式数量 (发布/订阅 × 主动/被动)
BLE_MSG_TIME_OUT = 6000      // 消息超时 (ms)
ADV_INTERNAL = 48            // 广播间隔 (ms)
BROADCAST_MAX_LEN = 50       // 广播数据最大长度
BLE_ADV_TX_POWER_DEFAULT = -6  // 默认广播功率 (dBm)
```
