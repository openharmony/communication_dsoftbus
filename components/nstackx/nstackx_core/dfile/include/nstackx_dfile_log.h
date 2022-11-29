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
 
#ifndef NSTACKX_DFILE_LOG_H
#define NSTACKX_DFILE_LOG_H
 
#include "nstackx_dfile.h"
#include "nstackx_log.h"
#ifdef __cplusplus
extern "C" {
#endif
 
uint32_t GetDFileLogLevel(void);
void SetDFileLogLevel(uint32_t logLevel);
#define DFILE_LOG_COMMON NSTACKX_LOG_COMMON
 
#define DFILE_LOGF(moduleName, format, ...) \
    DFILE_LOG_COMMON(moduleName, DFILE_LOG_LEVEL_FATAL, GetDFileLogLevel(), format, ##__VA_ARGS__)
#define DFILE_LOGE(moduleName, format, ...) \
    DFILE_LOG_COMMON(moduleName, DFILE_LOG_LEVEL_ERROR, GetDFileLogLevel(), format, ##__VA_ARGS__)
#define DFILE_LOGW(moduleName, format, ...) \
    DFILE_LOG_COMMON(moduleName, DFILE_LOG_LEVEL_WARNING, GetDFileLogLevel(), format, ##__VA_ARGS__)
#define DFILE_LOGI(moduleName, format, ...) \
    DFILE_LOG_COMMON(moduleName, DFILE_LOG_LEVEL_INFO, GetDFileLogLevel(), format, ##__VA_ARGS__)
#define DFILE_LOGD(moduleName, format, ...) \
    DFILE_LOG_COMMON(moduleName, DFILE_LOG_LEVEL_DEBUG, GetDFileLogLevel(), format, ##__VA_ARGS__)

#ifdef __cplusplus
}
#endif
#endif /* #ifndef NSTACKX_DFILE_LOG_H */