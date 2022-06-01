/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef SOFTBUS_ADAPTER_LOG_H
#define SOFTBUS_ADAPTER_LOG_H

#include <stdio.h>
#include <stdbool.h>

#ifndef SOFTBUS_DEBUG
#if defined(__LITEOS_M__)
#define SOFTBUS_PRINTF
#include "log.h"
#else
#include "hilog/log.h"
#endif
#endif

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#ifndef SOFTBUS_DEBUG
#if defined(__LITEOS_M__)

#define LOG_DBG(fmt, ...) HILOG_DEBUG(HILOG_MODULE_SOFTBUS, fmt"\n", ##__VA_ARGS__);
#define LOG_INFO(fmt, ...) HILOG_INFO(HILOG_MODULE_SOFTBUS, fmt"\n", ##__VA_ARGS__);
#define LOG_WARN(fmt, ...) HILOG_WARN(HILOG_MODULE_SOFTBUS, fmt"\n", ##__VA_ARGS__);
#define LOG_ERR(fmt, ...) HILOG_ERROR(HILOG_MODULE_SOFTBUS, fmt"\n", ##__VA_ARGS__);
#else

#undef LOG_DOMAIN
#undef LOG_TAG
#define LOG_DOMAIN 0xD0015C0
#define LOG_TAG "dsoftbus"

#define LOG_DBG(fmt, ...) HILOG_DEBUG(LOG_CORE, fmt"\n", ##__VA_ARGS__);
#define LOG_INFO(fmt, ...) HILOG_INFO(LOG_CORE, fmt"\n", ##__VA_ARGS__);
#define LOG_WARN(fmt, ...) HILOG_WARN(LOG_CORE, fmt"\n", ##__VA_ARGS__);
#define LOG_ERR(fmt, ...) HILOG_ERROR(LOG_CORE, fmt"\n", ##__VA_ARGS__);
#endif
#else
enum {
    SOFTBUS_LOG_LEVEL_DEBUG = 0,
    SOFTBUS_LOG_LEVEL_INFO,
    SOFTBUS_LOG_LEVEL_WARNING,
    SOFTBUS_LOG_LEVEL_ERROR
};

#define SOFTBUS_LOG_LEVEL SOFTBUS_LOG_LEVEL_INFO

#define LOG_DBG(fmt, ...) do { \
    if (SOFTBUS_LOG_LEVEL_DEBUG >= SOFTBUS_LOG_LEVEL) { \
        printf("DEBUG:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_INFO(fmt, ...) do { \
    if (SOFTBUS_LOG_LEVEL_INFO >= SOFTBUS_LOG_LEVEL) { \
        printf("INFO:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_WARN(fmt, ...) do { \
    if (SOFTBUS_LOG_LEVEL_WARNING >= SOFTBUS_LOG_LEVEL) { \
        printf("WARN:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)

#define LOG_ERR(fmt, ...) do { \
    if (SOFTBUS_LOG_LEVEL_ERROR >= SOFTBUS_LOG_LEVEL) { \
        printf("ERROR:%s:%d " fmt "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
    } \
} while (0)
#endif

#if defined(__LITEOS_M__)
#define SOFTBUS_HILOG_ID HILOG_MODULE_SOFTBUS
#else
#define SOFTBUS_HILOG_ID LOG_CORE
#endif

typedef enum {
    SOFTBUS_LOG_DBG,
    SOFTBUS_LOG_INFO,
    SOFTBUS_LOG_WARN,
    SOFTBUS_LOG_ERROR,
    SOFTBUS_LOG_LEVEL_MAX,
} SoftBusLogLevel;

void SoftBusOutPrint(const char *buf, SoftBusLogLevel level);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
