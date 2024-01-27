/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

#ifndef DSOFTBUS_SOFTBUS_LOG_H
#define DSOFTBUS_SOFTBUS_LOG_H

#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>

#include "hilog/log.h"

#ifdef __cplusplus
extern "C" {
#endif

#if defined(__ICCARM__) || defined(__LITEOS_M__)
#define SOFTBUS_DPRINTF(fd, fmt, ...)
#else
#define SOFTBUS_DPRINTF(fd, fmt, ...) dprintf(fd, fmt, ##__VA_ARGS__)
#endif

#define LOG_TAG_MAX_LEN       16
#define MODULE_DOMAIN_MAX_LEN 32
#define LOG_LINE_MAX_LENGTH   512
#define NSTACKX_LOG_DOMAIN    0xd0057ff
#define DOMAIN_ID_TEST        0xd000f00

#define FILE_NAME        (__builtin_strrchr("/" __FILE__, '/') + 1)
#define FORMAT(fmt, ...) "[%{public}s:%{public}d] %{public}s# " fmt, FILE_NAME, __LINE__, __FUNCTION__, ##__VA_ARGS__

/* For inner use only */
#if defined(SOFTBUS_LITE_SYSTEM) || defined(SOFTBUS_SMALL_SYSTEM)
#define SOFTBUS_LITE_LOGF_INNER(label, ...) HILOG_FATAL(HILOG_MODULE_SOFTBUS, FORMAT(__VA_ARGS__))
#define SOFTBUS_LITE_LOGE_INNER(label, ...) HILOG_ERROR(HILOG_MODULE_SOFTBUS, FORMAT(__VA_ARGS__))
#define SOFTBUS_LITE_LOGW_INNER(label, ...) HILOG_WARN(HILOG_MODULE_SOFTBUS, FORMAT(__VA_ARGS__))
#define SOFTBUS_LITE_LOGI_INNER(label, ...) HILOG_INFO(HILOG_MODULE_SOFTBUS, FORMAT(__VA_ARGS__))
#define SOFTBUS_LITE_LOGD_INNER(label, ...) HILOG_DEBUG(HILOG_MODULE_SOFTBUS, FORMAT(__VA_ARGS__))
#else
#define SOFTBUS_LOG_INNER(level, label, ...) \
    HILOG_IMPL(LOG_CORE, level, label.domain, label.tag, FORMAT(__VA_ARGS__))
#endif // SOFTBUS_LITE_SYSTEM || SOFTBUS_SMALL_SYSTEM

typedef struct {
    int32_t label;
    uint32_t domain;
    char tag[LOG_TAG_MAX_LEN];
} SoftBusLogLabel;

void NstackxLogInnerImpl(const char *moduleName, uint32_t logLevel, const char *fmt, ...);

#define CHECK_AND_RETURN_RET_LOG_INNER(cond, ret, log, label, fmt, ...) \
    do {                                                                \
        if (!(cond)) {                                                  \
            log(label, fmt, ##__VA_ARGS__);                             \
            return ret;                                                 \
        }                                                               \
    } while (0)

#define CHECK_AND_RETURN_LOG_INNER(cond, log, label, fmt, ...) \
    do {                                                       \
        if (!(cond)) {                                         \
            log(label, fmt, ##__VA_ARGS__);                    \
            return;                                            \
        }                                                      \
    } while (0)

#ifdef __cplusplus
}
#endif
#endif // DSOFTBUS_SOFTBUS_LOG_H
