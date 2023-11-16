/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#include "nstackx.h"
#include "nstackx_log.h"

#ifdef __cplusplus
extern "C" {
#endif

#ifdef ENABLE_USER_LOG
uint32_t GetDFinderLogLevel(void);
void SetDFinderLogLevel(uint32_t logLevel);
#define DFINDER_LOG_COMMON NSTACKX_LOG_COMMON

#define DFINDER_LOGF(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, DFINDER_LOG_LEVEL_FATAL, GetDFinderLogLevel(), format, ##__VA_ARGS__)
#define DFINDER_LOGE(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, DFINDER_LOG_LEVEL_ERROR, GetDFinderLogLevel(), format, ##__VA_ARGS__)
#define DFINDER_LOGW(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, DFINDER_LOG_LEVEL_WARNING, GetDFinderLogLevel(), format, ##__VA_ARGS__)
#define DFINDER_LOGI(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, DFINDER_LOG_LEVEL_INFO, GetDFinderLogLevel(), format, ##__VA_ARGS__)
#define DFINDER_LOGD(moduleName, format, ...) \
    DFINDER_LOG_COMMON(moduleName, DFINDER_LOG_LEVEL_DEBUG, GetDFinderLogLevel(), format, ##__VA_ARGS__)
#else

#define DFINDER_LOGF LOGF
#define DFINDER_LOGE LOGE
#define DFINDER_LOGW LOGW
#define DFINDER_LOGI LOGI
#define DFINDER_LOGD LOGD

#endif

#ifdef __cplusplus
}
#endif

#endif /* #ifndef NSTACKX_DFINDER_LOG_H */
