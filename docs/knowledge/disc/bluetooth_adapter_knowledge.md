# Bluetooth 适配层 精练知识库

---

## 一、模块功能

SoftBus 对 OHOS 蓝牙框架的统一适配层。封装 BLE GATT Client/Server、BLE 广播/扫描、蓝牙状态管理，屏蔽底层蓝牙接口差异。

**核心职责**：
- 蓝牙状态管理与多监听器分发
- GATT Client：连接、服务发现、写特征值（带流控）
- GATT Server：注册、添加服务/特征/描述符、发送通知（带流控）
- BLE 广播：通道池管理、数据组装（TLV）、启停控制
- BLE 扫描：多通道扫描、过滤器合并、结果解析分发
- 多协议策略分发（BLE/SLE）

**关键 API**：

| API | 说明 |
|-----|------|
| `SoftBusBtInit()` | 初始化蓝牙适配层，注册 GAP 回调 |
| `SoftBusAddBtStateListener()` | 注册蓝牙状态监听（最多 23 个） |
| `InitSoftbusAdapterClient/Server()` | 初始化 GATT Client/Server |
| `SoftBusGattsSendNotify()` | GATT Server 发送通知（带流控） |
| `InitBroadcastMgr()` | 初始化广播管理器 |
| `StartBroadcasting/StartScan` | 启动广播/扫描 |
| `RegisterBroadcastMediumFunction()` | 注册协议策略实现（策略模式入口） |

---

## 二、代码组织

```
bluetooth/
├── common/       bt_common.c — 蓝牙状态管理、GAP 回调、监听器分发
│                 bt_common_virtual.c — 不支持 BT 平台的桩实现
├── ble/          gatt_client.c — GATT Client 连接/写/流控
│                 gatt_server.c — GATT Server 注册/服务/通知/流控
├── broadcast/
│   ├── interface/  broadcast_manager.h — 广播管理对外接口（~30 API）
│   ├── adapter/ble/ ble_gatt.c — BLE 广播/扫描适配器、通道池
│   │                 ble_utils.c — TLV 解析、类型转换
│   └── manager/    broadcast_mgr.c — 广播/扫描管理核心
│                   broadcast_mgr_utils.c — 异步回调辅助
└── net_bluetooth.gni — 编译配置
```

**核心数据结构**：

| 结构体 | 用途 | 位置 |
|--------|------|------|
| `StateListener[23]` | 蓝牙状态监听器数组 | bt_common.c |
| `SoftBusGattcManager` | GATT Client 回调注册节点（链表） | gatt_client.c |
| `ServerService` | GATT Server 服务节点（链表） | gatt_server.c |
| `SoftBusBleSendSignal` | 写/通知流控信号（mutex+cond+flag） | gatt_client/server.c |
| `AdvChannel[21]` / `ScanChannel[4]` | 广播/扫描通道池 | ble_gatt.c |
| `BroadcastManager[BC_NUM_MAX]` | 广播管理槽位（含 4 个 cond） | broadcast_mgr.c |
| `ScanManager[SCAN_NUM_MAX]` | 扫描管理槽位（含过滤器） | broadcast_mgr.c |
| `g_interface[MEDIUM_NUM_MAX]` | 策略模式函数表 | broadcast_mgr.c |

---

## 三、架构设计约束与规则

### 设计模式

| 模式 | 说明 | 位置 |
|------|------|------|
| **策略模式** | `g_interface[]` 存储协议函数表，管理器通过接口分发不感知具体协议 | broadcast_mgr.c → RegisterBroadcastMediumFunction |
| **观察者模式** | 蓝牙状态变化分发给 23 个监听器 | bt_common.c → SoftBusOnBtSateChanged |
| **通道池** | 固定大小数组 + isUsed 标志 + mutex 保护 | ble_gatt.c → g_advChannel/g_scanChannel |
| **流控信号** | mutex + cond + isWriteAvailable 实现串行化写/通知 | gatt_client.c/gatt_server.c |
| **适配器/包装器** | `Wrapper*` 函数将 OHOS BT 回调转换为 SoftBus 事件 | bt_common.c |
| **桩实现** | `_virtual.c` 对不支持 BT 的平台返回 `SOFTBUS_FUNC_NOT_SUPPORT` | bt_common_virtual.c |

### 线程模型

**三个线程上下文**：
1. **业务线程** — 上层调用 StartBroadcasting/StartScan 等
2. **BT 回调线程** — OHOS BT 框架回调（Wrapper*Cb）
3. **Looper 线程** — 异步回调投递（broadcast_mgr_utils.c）

**锁列表**（10 把，无嵌套获取）：

| 锁 | 保护对象 |
|----|----------|
| `g_lock` | BLE/BR 开关状态 |
| `g_softBusGattcManager->lock` | Client 注册链表 |
| `g_btAddrs->lock` | MAC 地址追踪链表 |
| `g_clientSendSignal.sendCondLock` | Client 写流控 |
| `g_softBusGattsManager.lock` | Server 服务/连接列表 |
| `g_serverSendSignal.sendCondLock` | Server 通知流控 |
| `g_advLock` | 广播通道池 [21] |
| `g_scannerLock` | 扫描通道池 [4] |
| `g_bcLock` | 广播管理槽位数组 |
| `g_scanLock` | 扫描管理槽位数组 |

**原子变量**：`g_halServerId`、`g_halRegFlag`（Server 注册状态机 -1/0/1）、`g_isRegisterHalCallback`、`g_init`、`g_bcCbReg`

### 关键约束规则

1. **回调不能持锁** — 先拷贝回调到栈上，解锁后再调用（防死锁）
2. **流控必须超时** — GATT 写/通知操作通过 cond 等待，必须设超时防永久阻塞
3. **BT 关闭强制清理** — 收到 BLE_TURN_OFF 时停止所有广播/扫描，重置通道状态
4. **广播启停限流** — Start/Stop 之间最小间隔 `BC_WAIT_TIME_MS=50ms`
5. **过滤器合并** — 同一扫描通道上多个监听器的过滤器合并后统一扫描，结果分别匹配分发
6. **GATT Server 注册自旋等待** — `CheckGattsStatus()` 用原子变量 + 自旋（3次/5ms）等待 HAL 注册完成
7. **策略模式注册时机** — 协议实现（如 BLE）在 `Init()` 时调用 `RegisterBroadcastMediumFunction` 注册到管理器

### 关键常量

```c
BT_STATUSChangeListener_LEN = 23   // 监听器上限
BC_NUM_MAX = 21                    // 广播通道池
SCAN_NUM_MAX = 4                   // 扫描通道池
BC_WAIT_TIME_MS = 50               // 广播启停最小间隔
SOFTBUS_APP_UUID = {0xEE, 0xFD}    // GATT 应用 UUID
```