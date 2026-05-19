# Discovery Manager 精练知识库

> 路径：`core/discovery/manager` | 源码 ~2045 行 | 4 个源文件

---

## 一、模块功能

设备发现服务的核心管理层。统一调度 COAP/BLE/USB/NFC 四种媒介的发现能力，管理发布(Publish)和订阅(Subscribe)服务的完整生命周期，通过能力位图(capability bitmap)将发现的设备精确分发到对应订阅者。

**核心职责**：
- 发布/订阅服务的注册、校验、调度、清理
- 四媒介（COAP/BLE/USB/NFC）统一调度，AUTO 模式同时触发 COAP+BLE
- 设备发现回调分发（按能力位图匹配订阅者）
- OS 账号约束管理（约束时停止所有媒介操作，解除后自动恢复）
- 设备显示名称多长度管理（18/21/24 字符截断）
- 能力调用次数限制与 DFX 统计

**关键 API**：

| API | 说明 |
|-----|------|
| `DiscMgrInit/Deinit()` | 初始化/反初始化，注册四种媒介 |
| `DiscPublishService()` | 外部应用发布服务 |
| `DiscStartDiscovery()` | 外部应用订阅发现 |
| `DiscPublish/DiscStartAdvertise()` | 内部模块发布/发现 |
| `DiscOnDeviceFound()` | 媒介层上报设备的统一入口（回调分发核心） |
| `DiscMgrDeathCallback()` | 进程死亡时清理该进程的所有发布/订阅 |
| `DiscSetDisplayName()` | 设置设备显示名称 |

---

## 二、代码组织

```
core/discovery/manager/
├── include/
│   ├── disc_manager.h        — 核心管理接口（Publish/Subscribe/DisplayName/Constraint）
│   ├── disc_mgr_config.h     — 能力调用次数限制配置接口
│   ├── softbus_disc_init.h   — 动态库注册初始化接口
│   └── softbus_disc_server.h — 服务端初始化/死亡回调接口
└── src/
    ├── disc_manager.c (1661行) — 核心管理逻辑：发布/订阅/分发/约束
    ├── disc_mgr_config.c (89行) — 各能力的最大调用次数配置表
    ├── softbus_disc_init.c (42行) — dlsym 动态加载 DiscRegisterOpenFunc
    └── softbus_disc_server.c (40行) — 服务端薄封装层
```

**代码量分布**：核心管理 82% | 配置 5% | 接口定义 5% | 服务端 4% | 动态加载 4%

**核心数据结构**：

| 结构体 | 用途 |
|--------|------|
| `DiscItem` | 包名维度节点：packageName + callback + callTimes + 内嵌 DiscInfo 链表 |
| `DiscInfo` | 单条发布/订阅节点：id/mode/medium + capNode（挂到能力索引链表） |
| `InnerOption` | PublishOption/SubscribeOption 联合体 |
| `InnerCallback` | 外部应用/内部模块回调联合体 |
| `g_capabilityList[CAPABILITY_MAX_BITNUM]` | 能力位图索引链表数组（设备发现分发核心） |
| `g_publishInfoList / g_discoveryInfoList` | SoftBusList，发布/订阅管理列表 |

**双层列表结构**：
```
g_publishInfoList (SoftBusList)
  └── DiscItem(pkgName="com.app.a")
  │     └── InfoList → DiscInfo(id=1) → DiscInfo(id=2)
  └── DiscItem(pkgName="MODULE_LNN")
        └── InfoList → DiscInfo(id=10)

g_capabilityList[DDMP_BITMAP]  (能力索引)
  └── capNode → DiscInfo(id=5, pkgA) → DiscInfo(id=8, pkgB)
```

---

## 三、架构设计约束与规则

### 设计模式

| 模式 | 说明 | 位置 |
|------|------|------|
| **策略模式** | `DiscoveryFuncInterface` 函数指针表，四种媒介各自实现，管理器通过 `CallSpecificInterfaceFunc` 统一调度 | disc_manager.c:260 |
| **观察者模式** | `g_capabilityList[bitmap]` 实现能力位图订阅，设备发现时遍历匹配的观察者列表分发通知 | disc_manager.c:419 |
| **双层列表** | 外层 SoftBusList（按包名） + 内层 InfoList（按 ID） + capNode（挂到能力索引），三个维度管理同一批 DiscInfo | disc_manager.c |
| **内外分离** | ServiceType 枚举区分内部/外部调用，回调分发、列表插入顺序（头/尾）、包名校验分别处理 | disc_manager.c |

### 线程模型

**两个 SoftBusList 各一把锁**（无嵌套获取）：

| 锁 | 保护范围 | 并发特性 |
|----|----------|----------|
| `g_publishInfoList->lock` | 发布列表及所有 DiscItem/DiscInfo | 发布操作互斥 |
| `g_discoveryInfoList->lock` | 订阅列表 + `g_capabilityList[]` | 订阅和发现分发互斥 |

**线程上下文**：
- 外部 API 调用线程
- 媒介层回调线程（DiscOnDeviceFound 在此执行）

**并发特性**：发布和订阅使用独立锁，允许并行操作。约束处理中两锁顺序获取不嵌套。

### 关键约束规则

1. **DiscOnDeviceFound 持 discovery 锁** — 此回调内不可再调用管理器接口（死锁风险）
2. **约束状态仅记录不执行** — 约束启用时，发布/订阅只记录到列表不调用媒介；解除后自动恢复
3. **AUTO = COAP + BLE** — 任一成功即视为成功
4. **callTimes 限制** — 部分能力（CASTPLUS/DVKIT/OSD/SHARE/TOUCH/OOP/HA_INTERCONNECT）限制 32 次并发调用
5. **g_displayName 无锁** — 依赖调用方串行保证
6. **进程死亡清理** — 遍历清除该包名/pid 下所有发布和订阅信息
7. **回调分发边界** — 发现设备后，按 device.capabilityBitmap 每一位查找 g_capabilityList，只通知匹配的订阅者

### 关键常量

```c
DISC_INFO_LIST_SIZE_MAX = 1024    // 单包名最大 DiscInfo 数
DEFAULT_CALL_TIMES = 32           // 受限能力调用上限
NO_LIMITED_TIMES = -1             // 不限调用次数
PKG_NAME_SIZE_MAX = 128           // 包名最大长度
DISPLAY_NAME_BUF_LEN = 128       // 设备名缓冲区
```
