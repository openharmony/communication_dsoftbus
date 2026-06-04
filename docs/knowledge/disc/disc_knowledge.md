# 发现子系统 汇总知识库

## 一、四层架构与调用关系

```
┌─────────────────────────────────────────────────────────────────┐
│  应用层 / 内部模块                                               │
│  DiscPublishService() / DiscStartDiscovery() / DiscPublish()    │
└──────────────────────────────┬──────────────────────────────────┘
                               │ 策略模式调度（CallInterfaceByMedium）
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  L1: Discovery Manager (disc_manager.c)                         │
│  职责：发布/订阅生命周期管理、四媒介调度、能力位图分发              │
│  关键结构：g_publishInfoList / g_discoveryInfoList              │
│            g_capabilityList[bitmap] / DiscoveryFuncInterface    │
└──────────────────────────────┬──────────────────────────────────┘
                               │ DiscoveryFuncInterface 函数指针
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  L2: BLE 发现 (disc_ble.c)                                      │
│  职责：BLE 广播/扫描、TLV 编解码、消息驱动、能力引用计数           │
│  关键结构：g_bleInfoManager[4] / g_bleAdvertiser[2]             │
│            DiscBleMessage(16种) / g_discBleHandler(Looper)      │
└──────────────────────────────┬──────────────────────────────────┘
                               │ broadcast_scheduler 接口
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  L3: Bluetooth 适配层 (broadcast_mgr.c + ble_gatt.c)            │
│  职责：广播/扫描通道池管理、协议策略分发、BLE 数据组装/解析        │
│  关键结构：g_bcManager[] / g_scanManager[] / g_advChannel[21]   │
│            g_scanChannel[4] / g_interface[MEDIUM_NUM_MAX]       │
└──────────────────────────────┬──────────────────────────────────┘
                               │ OHOS BT Framework API
                               ▼
┌─────────────────────────────────────────────────────────────────┐
│  L4: OHOS Bluetooth Framework                                   │
│  BleStartAdvEx / BleStartScanEx / BleGattc* / BleGatts* / ...  │
└─────────────────────────────────────────────────────────────────┘
```

## 二、端到端数据流

### 发布服务（主动发布）

```
应用 → DiscPublishService(pkg, info)
     → DiscMgr: InnerPublishService → AddDiscInfoToPublishList → CallInterfaceByMedium(BLE)
     → DiscBle: BleStartActivePublish → ProcessBleDiscFunc → PostMessage(PUBLISH_ACTIVE_SERVICE)
     → Looper: DiscBleMsgHandler → StartActivePublish → StartAdvertiser(NON)
     → BroadcastAdapter: RegisterBroadcaster → StartBroadcasting → SoftbusStartAdv
     → OHOS BT: BleStartAdvEx
```

### 设备发现（扫描结果上报）

```
OHOS BT → WrapperScanResultCb
        → BroadcastAdapter: ParseScanResult(TLV) → BcReportScanDataCallback
        → DiscBle: BleScanResultCallback → ScanFilter → ProcessDistributePacket
        → DiscBle: GetDeviceInfoFromDisAdvData(TLV解码) → RangeDevice → ProcessHashAccount
        → DiscMgr: DiscOnDeviceFound → 遍历 g_capabilityList[bitmap]
        → DiscMgr: InnerDeviceFound → serverCb.OnServerDeviceFound / innerCb.OnDeviceFound
        → 应用层回调
```

### 蓝牙状态变化

```
OHOS BT GAP → WrapperStateChangeCallback
            → BT Common: IsRepeatNotify → SoftBusOnBtSateChanged → 分发23个监听器
            → BroadcastMgr: BcBtStateChanged → HandleOnStateOff（停止所有广播/扫描）
            → DiscBle: BtOnStateChanged → PostMessage(RECOVERY/TURN_OFF)
            → DiscBle Looper: 恢复或停止所有广播和扫描
```

## 三、跨模块共享设计模式

| 模式 | L1 DiscMgr | L2 DiscBle | L3 BT Adapter |
|------|-----------|-----------|---------------|
| **策略模式** | DiscoveryFuncInterface 四媒介调度 | DiscoveryFuncInterface 暴露给上层 | SoftbusBroadcastMediumInterface 多协议分发 |
| **观察者模式** | g_capabilityList[bitmap] 设备发现分发 | — | StateListener[23] BT 状态分发 |
| **桩实现** | — | disc_ble_virtual.c | bt_common_virtual.c |
| **通道池** | — | — | AdvChannel[21] / ScanChannel[4] / BcManager[] / ScanManager[] |
| **Handler-Looper** | — | DiscBleMsgHandler（核心驱动） | — |
| **引用计数** | callTimes[bitmap] | capCount[pos] | — |
| **流控信号** | — | — | SoftBusBleSendSignal（mutex+cond+flag） |

## 四、跨模块一致的约束规则

### 线程安全规则

| 规则 | 适用范围 |
|------|----------|
| **回调不能持锁** | L3（BT 适配层）：先拷贝回调到栈，解锁后调用 |
| **DiscOnDeviceFound 持 discovery 锁** | L1（DiscMgr）：回调内不可再调管理器接口 |
| **扫描回调可持 g_bleInfoLock** | L2（DiscBle）：但不能同时持 recvMessageInfo.lock |
| **外部接口只 PostMessage** | L2（DiscBle）：不直接操作硬件，保证 Looper 串行 |

### 资源管理规则

| 规则 | 适用范围 |
|------|----------|
| **固定大小池** | L3：广播通道 21 个、扫描通道 4 个，不可动态扩展 |
| **引用计数到 0 才清除** | L2：capCount[pos] 引用计数 |
| **超时自动清理** | L2：RecvMessage 6 秒超时；L3：GATT 写/通知 cond 超时 |
| **进程死亡清理** | L1：DiscMgrDeathCallback 清除该进程所有发布/订阅 |
| **BT 关闭强制重置** | L2+L3：收到 BLE_TURN_OFF 停止一切，重置通道状态 |

### 调用链路规则

| 规则 | 说明 |
|------|------|
| **L1 → L2 异步** | DiscMgr 调用 DiscBle 的 Publish/Subscribe，DiscBle 通过 PostMessage 异步执行 |
| **L2 → L3 同步+异步** | DiscBle 调用 broadcast_scheduler 启停广播/扫描，操作完成通过回调通知 |
| **L3 → L4 同步+回调** | BT Adapter 调用 OHOS BT API（同步），结果通过 Wrapper*Cb 回调 |
| **数据流向单向** | 回调链路：L4 → L3 → L2 → L1 → 应用；调用链路反向 |
| **AUTO = COAP + BLE** | L1 中 AUTO 媒介同时调用两种，任一成功即可 |

## 五、关键能力位图映射

| 位 | 能力 | 调用限制 | 涉及模块 |
|----|------|----------|----------|
| 2 | CASTPLUS | 32 | DiscBle + BT Adapter |
| 4 | DVKIT | 32 | DiscBle + BT Adapter |
| 6 | OSD | 32 | DiscBle + BT Adapter |
| 7 | SHARE | 32 | DiscBle + BT Adapter |
| 其他 | HICALL/PROFILE/AA/DDMP 等 | 不限 | 视媒介而定 |

BLE 模块关心：`g_concernCapabilityMask = CAST | DVKIT | OSD`

## 六、快速参考

### 初始化顺序

```
DiscMgrInit → DiscCoapInit / DiscBleInit / DiscUsbInit / DiscNfcInit
                        │
            DiscSoftBusBleInit → SchedulerInitBroadcast → DiscBleLooperInit
                        │
                InitBroadcastMgr → RegisterBroadcastMediumFunction(BLE)
                        │
                SoftBusBtInit → GapRegisterCallbacks
```

### 关键超时与间隔

| 参数 | 值 | 模块 |
|------|-----|------|
| 广播间隔 | 48ms | DiscBle (ADV_INTERNAL) |
| 消息超时 | 6000ms | DiscBle (BLE_MSG_TIME_OUT) |
| 广播启停间隔 | 50ms | BT Adapter (BC_WAIT_TIME_MS) |
| GATT 写超时 | 动态计算 | BT Adapter (SoftBusComputeWaitBleSendDataTime) |
| DFX 上报间隔 | 定时 | DiscBle (DFX_DELAY_RECORD) |


## 子模块索引

| 子模块 | 文档 | 核心职责 | 源码 |
|--------|------|----------|------|
| Discovery Manager | [disc_manager_knowledge.md](disc_manager_knowledge.md) | 发布/订阅生命周期管理、四媒介调度、能力位图分发 | `core/discovery/manager/` |
| BLE 发现 | [disc_ble_knowledge.md](disc_ble_knowledge.md) | BLE 广播/扫描、TLV 编解码、Handler-Looper 消息驱动 | `core/discovery/ble/` |
| Bluetooth 适配层 | [bluetooth_adapter_knowledge.md](bluetooth_adapter_knowledge.md) | GATT Client/Server、广播/扫描通道池、蓝牙状态管理 | `adapter/bluetooth/` |

**快速路由**：
- 发布/订阅管理、能力分发 → disc_manager_knowledge.md
- BLE 广播数据组装/解析、消息驱动 → disc_ble_knowledge.md
- GATT 操作、通道池、蓝牙状态监听 → bluetooth_adapter_knowledge.md