# DSoftBus 仓库指南

## 项目结构与模块组织

DSoftBus 是 OpenHarmony 的分布式软总线组件，提供统一的近场设备通信能力。核心服务逻辑位于 `core/`；客户端/代理代码位于 `sdk/`；对外接口位于 `interfaces/`。平台适配代码位于 `adapter/`。测试代码位于 `tests/`。共享工具和公共定义位于 `core/common/`。运行时配置位于 `adapter/default_config/`。

**核心架构**：应用层 → SDK 层 → 服务层 → 适配层 → 操作系统

**主要功能**：设备发现、连接、组网、传输、选路

---

## 构建命令

从 OpenHarmony 源码根目录运行构建命令，而非此子目录。

```sh
./build.sh --product-name <产品名> --build-target dsoftbus --ccache
```

---

## 测试指南

单元测试和模糊测试位于 `tests/`。使用现有测试框架，在更改核心逻辑、API 行为或事件处理时将测试添加到最接近的模块。保持测试确定性并清理全局状态。

---

## 提交与拉取请求指南

保持每次提交仅包含一个逻辑更改。使用描述性的提交信息。PR 应总结行为变更、列出受影响的模块并包含测试证据。

---

## 架构原则

保持清晰的分层：应用 → SDK → 服务 → 适配 → 操作系统。避免将策略决策混入底层传输代码。使用上下文对象而非分散的全局状态。维护 `core/`、`sdk/` 和 `adapter/` 之间的清晰所有权。

---

## Agent规范

- **记忆**：`.task/<task context>` 持续压缩保存上下文，每次新开窗口询问用户是否加载旧对话上下文
- **知识构建**：对于交互使用中反复提及或者纠正的问题，询问用户是否写入对应的知识库文档中；

---

## DSoftBus 知识库

### 知识库结构

- **模块**：公共知识、领域知识
- **加载**：公共知识直接加载，领域知识按需加载

### 公共知识

稳定的 DSoftBus 知识位于 `docs/knowledge/`。在以下进行代码更改前，请先阅读对应文件：

| 领域 | 首先阅读 |
| --- | --- |
| DSoftBus特有规范、关键约束 | `docs/knowledge/coding_standards.md` |

### 领域知识

**加载规则**：在操作对应源码时，优先根据知识库索引加载对应知识库文档
**命名规则**：`目录名_knowledge.md`（例如 `core/connection/connection_knowledge.md`）

**知识库索引**
| 子模块 | 功能 | 源码 |
| --- | --- | --- |
| 发现 | 设备广播、发现 | `docs/knowledge/disc/disc_knowledge.md` |
| 连接 | 设备物理通道建立、管理 | `core/connection/connection_knowledge.md` |
| 组网 | 设备组网、认证 | `docs/knowledge/lnn/lnn_knowledge.md` |
| 传输 | 传输通道建立、管理 | `core/transmission/transmission_knowledge.md` |

---

**文档版本**：v3.0 | **更新**：2026-05-15
