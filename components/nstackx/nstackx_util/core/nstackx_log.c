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
#include "nstackx_error.h"
#define TAG "nStackXLog"
static uint32_t g_logLevel = NSTACKX_LOG_LEVEL_INFO;

#ifdef BUILD_FOR_WINDOWS
static void DefaultLogImpl(const char *tag, uint32_t level, const char *format, va_list args)
{
    SYSTEMTIME st = {0};

    GetLocalTime(&st);
    printf("%02u-%02u %02u:%02u:%02u.%03u %d %d %d %s: ", st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
           st.wMilliseconds, GetCurrentProcessId(), GetCurrentThreadId(), level, tag);
    vprintf(format, args);
}

static LogImplInternal g_logImpl = DefaultLogImpl;
#endif

uint32_t GetLogLevel(void)
{
    return g_logLevel;
}

void SetLogLevel(uint32_t logLevel)
{
    if (logLevel >= NSTACKX_LOG_LEVEL_END) {
        return;
    }
    g_logLevel = logLevel;
}

void SetLogImpl(LogImplInternal fn)
{
    if (fn == NULL) {
        return;
    }
}
#ifdef BUILD_FOR_WINDOWS
#ifndef NEED_EXPORT_VARIABLE
#define NEED_EXPORT_VARIABLE
#endif
#endif

NstakcxLogCallback g_nstackxLogCallBack = PrintfImpl;

int32_t SetLogCallback(NstakcxLogCallback logCb)
{
    if (logCb == NULL) {
        LOGE(TAG, "log callback is null");
        return NSTACKX_EINVAL;
    }
    if (logCb == g_nstackxLogCallBack) {
        LOGW(TAG, "log callback is the same");
        return NSTACKX_EOK;
    }
    LOGI(TAG, "log callback changed");
    g_nstackxLogCallBack = logCb;
    return NSTACKX_EOK;
}

void SetDefaultLogCallback(void)
{
    g_nstackxLogCallBack = PrintfImpl;
    return;
}