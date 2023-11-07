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
#include <string.h>

#if defined(__LITEOS_M__)
#define SOFTBUS_PRINTF
#include "log.h"
#else
#include "hilog/log.h"
#endif

static void SoftBusLogExtraInfoFormat(char *str, const char *fileName, int lineNum, const char *funName)
{
    (void)sprintf_s(str, sizeof(str), "[%s:%d] %s# ", fileName, lineNum, funName);
}

static void SoftBusLogPrint(const char *buf, SoftBusLogLevel level, unsigned int domain, const char *tag)
{
#ifdef SOFTBUS_PRINTF
    (void)level;
    (void)domain;
    (void)tag;
    printf("%s\n", buf);
#else
    (void)HiLogPrint(LOG_CORE, (LogLevel)level, domain, tag, "%{public}s", buf);
#endif
}

void SoftBusLogInnerImpl(SoftBusLogLevel level, SoftBusLogLabel label, const char *fileName, int lineNum,
    const char *funName, const char *fmt, ...)
{
    uint32_t ulPos;
    char szStr[LOG_LINE_MAX_LENGTH] = { 0 };
    va_list arg;

    SoftBusLogExtraInfoFormat(szStr, fileName, lineNum, funName);
    ulPos = strlen(szStr);
    (void)memset_s(&arg, sizeof(va_list), 0, sizeof(va_list));
    va_start(arg, fmt);
    (void)vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, fmt, arg);
    va_end(arg);
    SoftBusLogPrint(szStr, level, label.domain, label.tag);
}
