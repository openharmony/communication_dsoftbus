# DSoftBus 代码规范知识

> DSoftBus 特有规范，业界通用规范从略。

---

## 模块前缀

```c
LnnGetLocalNodeInfo()     // 组网
TransSendData()           // 传输
ConnConnectDevice()       // 连接
DiscStartDiscovery()      // 发现
AuthStartVerify()         // 认证
SoftBusMalloc()           // 适配层
```

---

## 核心常量

```c
// core/common/include/softbus_def.h
#define INVALID_SESSION_ID    (-1)
#define SESSION_NAME_SIZE_MAX 256
#define BT_MAC_LEN           18
#define IP_LEN               46
```

---

## 适配层函数

```c
// 必须使用（支持追踪、统计）
void *SoftBusMalloc(unsigned int size);
void SoftBusFree(void *pt);
SoftBusMutexLock(&mutex);  // 不用 pthread_mutex_lock
```

---

## 关键约束

- **检查返回值**：`if (SomeFunction() != SOFTBUS_OK) { /* 处理 */ }`
- **检查内存分配**：`if ((buffer = SoftBusMalloc(size)) == NULL) { return SOFTBUS_MALLOC_ERR; }`
- **跨线程加锁**：`SoftBusMutexLock(&mutex)` / `SoftBusMutexUnlock(&mutex)`
- **回调数据释放**：回调中的 `data` 必须由接收者使用 `SoftBusFree()` 释放
- **goto 清理资源**：使用 `goto CLEANUP` 统一清理资源

---

## DSoftBus 通用陷阱

### 特性宏

```c
#ifdef DSOFTBUS_FEATURE_DISC_COAP
    // CoAP 发现代码
#endif
```

**提醒**：特性宏命名规则 `DSOFTBUS_FEATURE_<模块>_<功能>`

---

**关键文件**：
- `core/common/include/softbus_def.h` - 常量定义
- `dfx/interface/include/softbus_log.h` - 日志接口
- `adapter/feature_config/public_feature.gni` - 特性配置

---

**文档版本**：v5.0 | **更新**：2026-05-15
