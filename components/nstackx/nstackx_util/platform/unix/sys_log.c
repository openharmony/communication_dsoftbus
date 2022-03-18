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

#include "nstackx_log.h"
#include "securec.h"
#ifdef ENABLE_DFINDER_HILOG
#include "hilog/log.h"
#endif

__attribute__((format(printf, 3, 4)))
void PrintfImpl(const char *moduleName, uint32_t logLevel, const char *format, ...)
{
    va_list args;

    va_start(args, format);
    printf("%u %s: ", logLevel, moduleName);
    vprintf(format, args);
    va_end(args);
}

#ifdef ENABLE_DFINDER_HILOG
#define LOG_PRINT_MAX_LEN 256
static void HiLogPrintWrapper(const char *tag, uint32_t domain, const char *buf, uint32_t logLevel)
{
    LogLevel hiLogLevel = LOG_ERROR;
    switch (logLevel) {
        case NSTACKX_LOG_LEVEL_DEBUG:
            hiLogLevel = LOG_DEBUG;
            break;
        case NSTACKX_LOG_LEVEL_INFO:
            hiLogLevel = LOG_INFO;
            break;
        case NSTACKX_LOG_LEVEL_WARNING:
            hiLogLevel = LOG_WARN;
            break;
        case NSTACKX_LOG_LEVEL_ERROR:
            hiLogLevel = LOG_ERROR;
            break;
        case NSTACKX_LOG_LEVEL_FATAL:
            hiLogLevel = LOG_FATAL;
            break;
        default:
            break;
    }
    if (tag == NULL || strlen(tag) == 0) {
        HiLogPrint(LOG_CORE, hiLogLevel, domain, NSTACKX_DEFAULT_TAG, "%{public}s", buf);
    } else {
        HiLogPrint(LOG_CORE, hiLogLevel, domain, tag, "%{public}s", buf);
    }
}

__attribute__((format(printf, 5, 6))) void NstackxHiLogImpl(const char *tag,
                                                            uint32_t domain,
                                                            const char *moduleName,
                                                            uint32_t logLevel,
                                                            const char *format,
                                                            ...)
{
    uint32_t ulPos;
    char szStr[LOG_PRINT_MAX_LEN] = {0};
    va_list args;
    int32_t ret;

    ret = sprintf_s(szStr, sizeof(szStr), "%u %s: ", logLevel, moduleName);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "[DISC]softbus log error");
        return;
    }
    ulPos = strlen(szStr);
    (void)memset_s(&args, sizeof(va_list), 0, sizeof(va_list));
    va_start(args, format);
    ret = vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, format, args);
    va_end(args);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "[DISC]softbus log len error");
        return;
    }
    HiLogPrintWrapper(tag, domain, szStr, logLevel);
    return;
}
#endif
