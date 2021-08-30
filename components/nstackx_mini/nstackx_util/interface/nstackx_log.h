/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_LOG_H
#define NSTACKX_LOG_H

#include "nstackx_common_header.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    NSTACKX_LOG_LEVEL_OFF     = 0,
    NSTACKX_LOG_LEVEL_FATAL   = 1,
    NSTACKX_LOG_LEVEL_ERROR   = 2,
    NSTACKX_LOG_LEVEL_WARNING = 3,
    NSTACKX_LOG_LEVEL_INFO    = 4,
    NSTACKX_LOG_LEVEL_DEBUG   = 5,
    NSTACKX_LOG_LEVEL_END,
};

#define NSTACKX_DEFAULT_TAG "nStackX"

/* Log module initialization */
NSTACKX_EXPORT void SetLogLevel(uint32_t logLevel);

/* Get current log level */
NSTACKX_EXPORT uint32_t GetLogLevel(void);

/* Actual implementation of "print", which is platform dependent */
NSTACKX_EXPORT void PrintfImpl(const char *moduleName, uint32_t logLevel, const char *format, ...);

/* internal log implementation for windows */
typedef void (*LogImplInternal)(const char *tag, uint32_t level, const char *format, va_list args);

/* Set log implementation */
NSTACKX_EXPORT void SetLogImpl(LogImplInternal fn);

#define NSTACKX_LOG_COMMON(moduleName, logLevel, format, ...) \
    do { \
        if (logLevel <= GetLogLevel()) { \
            PrintfImpl(moduleName, logLevel, "%s:[%d] :" format "\n", __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)

#define LOGF(moduleName, format, ...) NSTACKX_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)
#define LOGE(moduleName, format, ...) NSTACKX_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define LOGW(moduleName, format, ...) NSTACKX_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define LOGI(moduleName, format, ...) NSTACKX_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define LOGD(moduleName, format, ...) NSTACKX_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_LOG_H
