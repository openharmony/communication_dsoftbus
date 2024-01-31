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

#include "softbus_log.h"

#include <securec.h>

#define NSTACKX_LOG_LEVEL_CONVERT_BASE 8

static void SoftBusLogPrint(const char *line, uint32_t level, uint32_t domain, const char *tag)
{
#if defined(SOFTBUS_LITEOS_M)
    (void)level;
    (void)domain;
    (void)tag;
    printf("%s\n", line);
#else
    (void)HiLogPrint(LOG_CORE, (LogLevel)level, domain, tag, "%{public}s", line);
#endif
}

void NstackxLogInnerImpl(const char *moduleName, uint32_t logLevel, const char *fmt, ...)
{
    uint32_t level = NSTACKX_LOG_LEVEL_CONVERT_BASE - logLevel;
    va_list args = { 0 };
    char line[LOG_LINE_MAX_LENGTH + 1] = { 0 };
    va_start(args, fmt);
    int32_t ret = vsprintf_s(line, sizeof(line), fmt, args);
    va_end(args);
    if (ret < 0) {
        return; // Do not print log here
    }
    SoftBusLogPrint(line, level, NSTACKX_LOG_DOMAIN, moduleName);
}