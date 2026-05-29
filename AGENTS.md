# DSoftBus 仓库指引

## 代码地图

本仓库对应 OpenHarmony 分布式软总线组件，提供统一的近场设备通信能力。核心架构为 应用层 → SDK 层 → 服务层 → 适配层 → 操作系统，主要功能包括设备发现、连接、组网、传输、选路。保持清晰的分层，避免将策略决策混入底层传输代码，使用上下文对象而非分散的全局状态，维护 `core/`、`sdk/` 和 `adapter/` 之间的清晰所有权。

优先按这些目录定位问题：

- `core/`：核心服务逻辑，包含发现、连接、组网、传输等模块。
- `sdk/`：客户端/代理代码。
- `interfaces/`：对外接口。
- `adapter/`：平台适配代码。
- `core/common/`：共享工具和公共定义。
- `adapter/default_config/`：运行时配置。
- `tests/`：单元测试。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
./build.sh --product-name <产品名> --build-target dsoftbus --ccache
```

测试位于 `tests/`，使用现有测试框架，在更改核心逻辑、API 行为或事件处理时确保将测试添加到最接近的模块。保持测试确定性和清理全局状态。

## 知识索引

稳定背景知识放在 `docs/knowledge/` 及各模块目录下。改动前按场景读取对应文件：

| 场景 | 先读 |
| --- | --- |
| 设备发布、发现、BLE广播/扫描、能力位图、蓝牙适配 | `docs/knowledge/disc/disc_knowledge.md` |
| 连接协议（BLE/BR/SLE/TCP/WiFi Direct）、连接管理、引用计数 | `core/connection/connection_knowledge.md` |
| 设备认证、密钥协商、上下线、拓扑管理、心跳保活、离线检测、系统事件 | `docs/knowledge/lnn/lnn_knowledge.md` |
| 通道建立/关闭、权限校验、链路切换、UDP/TCP/Proxy/Auth通道 | `core/transmission/transmission_knowledge.md` |

领域知识遵循 `目录名_knowledge.md` 命名规则，操作对应源码或用户描述包含对应场景时触发加载。

## 项目约束

- 所有对外函数以所属模块缩写为前缀命名（`LnnGetLocalNodeInfo()`、`TransSendData()`、`ConnConnectDevice()`、`DiscStartDiscovery()`），特性宏遵循 `DSOFTBUS_FEATURE_<模块>_<功能>` 格式。
- 内存分配/释放使用 `SoftBusMalloc()` / `SoftBusFree()`，互斥锁使用 `SoftBusMutexLock()` / `SoftBusMutexUnlock()`，禁止使用原生 C 库函数，否则 DFX 追踪统计能力缺失。
- 持锁状态下禁止直接调用回调函数，先解锁再回调；嵌套回调场景使用递归锁防死锁。
- 条件变量等待资源必须设超时，禁止无限等待。
- SDK 层所有调用必须传入 `pkgName` 进行权限校验；跨进程调用参数必须序列化/反序列化；新增 IPC 请求码不得复用已有值。
- 模块初始化时，不支持功能通过 `_virtual.c` 桩文件返回 `SOFTBUS_NOT_IMPLEMENT`。
- 平台差异通过适配层统一抽象，不在核心逻辑中直接调用平台 API；对短距操作必须通过连接模块封装，禁止直接调用短距API。
