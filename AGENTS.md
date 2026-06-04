# DSoftBus 仓库指引

## 代码地图

本仓库对应 OpenHarmony 分布式软总线组件，提供统一的近场设备通信能力。核心架构为 应用层 → SDK 层 → 服务层 → 适配层 → 操作系统，主要功能包括设备发现、连接、组网、传输、选路。保持清晰的分层，避免将策略决策混入底层传输代码，使用上下文对象而非分散的全局状态，维护 `core/`、`sdk/` 和 `adapter/` 之间的清晰所有权。

优先按这些目录定位问题：

- `core/`：核心服务逻辑，包含发现、连接、组网、传输等模块。
- `sdk/`：客户端/代理代码（无特殊约束，无需独立知识库）。
- `interfaces/`：对外接口。
- `adapter/`：平台适配代码（无特殊约束，无需独立知识库）。
- `core/common/`：共享工具和公共定义。
- `adapter/default_config/`：运行时配置。
- `tests/`：单元测试。

## 构建和验证

构建命令从 OpenHarmony 源码根目录执行，不在本子目录执行。

```sh
# 构建
./build.sh --product-name <产品名> --build-target dsoftbus --ccache

# 运行模块单元测试（示例，替换 <模块> 为实际目标）
./build.sh --product-name <产品名> --build-target <模块>_unittest
```

如仓库根目录存在 `.clang-format` 或 `.clang-tidy`，改动后运行对应检查。

测试位于 `tests/`，按模块组织（`tests/core/`、`tests/sdk/`、`tests/adapter/` 等）。在更改核心逻辑、API 行为或事件处理时确保将测试添加到最接近的模块。

### 完成定义

改动完成需满足：
1. 代码构建通过，且相关模块单元测试通过。
2. 已确认变更不涉及 `interfaces/kits/` 或 `interfaces/inner_kits/` 中的公共 API（或已标注需人工确认兼容性）。
3. 已确认变更不涉及认证、密钥、权限等安全相关逻辑（或已标注需人工确认安全影响）。

### 降级方案

如无法在本地执行构建或测试，在回复中明确说明：
- "以下变更未经本地构建验证"
- 列出需要人工验证的项目和原因

## 知识索引

稳定背景知识放在 `docs/knowledge/` 及各模块目录下。修改代码前，先根据场景或路径读取对应知识文档，并在回复中说明已读取的文档和发现的约束。

| 场景 | 先读 | 路径触发规则 |
| --- | --- | --- |
| 设备发布、发现、BLE广播/扫描、能力位图、蓝牙适配 | `docs/knowledge/disc/disc_knowledge.md` | `core/disc/` |
| 连接协议（BLE/BR/SLE/TCP/WiFi Direct）、连接管理、引用计数 | `core/connection/connection_knowledge.md` | `core/connection/` |
| 设备认证、密钥协商、上下线、拓扑管理、心跳保活、离线检测、系统事件 | `docs/knowledge/lnn/lnn_knowledge.md` | `core/lnn/` |
| 通道建立/关闭、权限校验、链路切换、UDP/TCP/Proxy/Auth通道 | `core/transmission/transmission_knowledge.md` | `core/transmission/` |

领域知识遵循 `目录名_knowledge.md` 命名规则，操作对应源码或用户描述包含对应场景时触发加载。

## 项目约束

### 必须确认后才能修改

- `interfaces/kits/` 或 `interfaces/inner_kits/` 下的头文件变更（公共 API 兼容性，修改前需确认不影响既有调用方）。
- 认证、密钥协商、设备信任、权限校验相关逻辑（安全边界，修改前需确认安全影响）。
- IPC 请求码枚举值（版本兼容性，事实来源：`core/common/include/softbus_server_ipc_interface_code.h`，禁止在回复中固化具体数值）。
- `BUILD.gn` 依赖方向变更（模块分层，修改前需确认不引入循环依赖或层级违反）。
- 协议编码格式、TLV 字段顺序、序列化结构变更（跨设备兼容性，修改前需确认不影响旧版本设备互通）。
- 代码修改会导致引入新的第三方依赖时。

### 必须遵循

- 所有对外函数以所属模块缩写为前缀命名（`LnnGetLocalNodeInfo()`、`TransSendData()`、`ConnConnectDevice()`、`DiscStartDiscovery()`），特性宏遵循 `DSOFTBUS_FEATURE_<模块>_<功能>` 格式。
- 内存分配/释放使用 `SoftBusMalloc()` / `SoftBusFree()`，互斥锁使用 `SoftBusMutexLock()` / `SoftBusMutexUnlock()`，禁止使用原生 C 库函数，否则 DFX 追踪统计能力缺失。
- 持锁状态下禁止直接调用回调函数，先解锁再回调。
- 条件变量等待资源必须设超时，禁止无限等待。
- 模块初始化时，不支持功能需要通过 `_virtual.c` 桩文件返回 `SOFTBUS_NOT_IMPLEMENT`。
- 平台差异通过适配层统一抽象，不在核心逻辑中直接调用平台 API；对短距操作必须通过连接模块封装，禁止直接调用短距API。
