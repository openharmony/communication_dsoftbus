/*
 * Copyright (C) 2022 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DFINDER_LOG_H
#define NSTACKX_DFINDER_LOG_H

#include "nstackx_common_header.h"
#include "nstackx_log.h"
#ifdef __cplusplus
extern "C" {
#endif

#define DFINDER_DEFAULT_TAG "nStackXDFinder"
#define LOG_DOMAIN 0xD0015C0

#ifdef ENABLE_DFINDER_HILOG
NSTACKX_EXPORT void NstackxHiLogImpl(const char *tag, uint32_t domain, const char *moduleName, uint32_t logLevel,
    const char *format, ...);
#define DFINDER_LOG_COMMON(moduleName, logLevel, format, ...) \
    do { \
        if (logLevel <= GetLogLevel()) { \
            NstackxHiLogImpl(DFINDER_DEFAULT_TAG, LOG_DOMAIN, moduleName, logLevel, "%s:[%d] :" format "\n", \
                __FUNCTION__, __LINE__, ##__VA_ARGS__); \
        } \
    } while (0)
#else
#define DFINDER_LOG_COMMON NSTACKX_LOG_COMMON
#endif

#define DFINDER_LOGF(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_FATAL, format, ##__VA_ARGS__)
#define DFINDER_LOGE(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_ERROR, format, ##__VA_ARGS__)
#define DFINDER_LOGW(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_WARNING, format, ##__VA_ARGS__)
#define DFINDER_LOGI(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_INFO, format, ##__VA_ARGS__)
#define DFINDER_LOGD(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, NSTACKX_LOG_LEVEL_DEBUG, format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif

#endif // NSTACKX_DFINDER_LOG_H
