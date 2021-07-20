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

#include "softbus_log.h"

#include <securec.h>

#define LOG_NAME_MAX_LEN 5
#define LOG_PRINT_MAX_LEN 256

typedef struct {
    SoftBusLogModule mod;
    char name[LOG_NAME_MAX_LEN];
} LogInfo;

static LogInfo g_logInfo[SOFTBUS_LOG_MODULE_MAX] = {
    {SOFTBUS_LOG_AUTH, "AUTH"},
    {SOFTBUS_LOG_TRAN, "TRAN"},
    {SOFTBUS_LOG_CONN, "CONN"},
    {SOFTBUS_LOG_LNN, "LNN"},
    {SOFTBUS_LOG_DISC, "DISC"},
    {SOFTBUS_LOG_COMM, "COMM"},
};

void SoftBusOutPrint(const char *buf, SoftBusLogLevel level)
{
    switch (level) {
        case SOFTBUS_LOG_DBG:
            HILOG_DEBUG(LOG_CORE, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_INFO:
            HILOG_INFO(LOG_CORE, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_WARN:
            HILOG_WARN(LOG_CORE, "%{public}s", buf);
            break;
        case SOFTBUS_LOG_ERROR:
            HILOG_ERROR(LOG_CORE, "%{public}s", buf);
            break;
        default:
            break;
    }
}

void SoftBusLog(SoftBusLogModule module, SoftBusLogLevel level, const char *fmt, ...)
{
    int ulPos;
    char szStr[LOG_PRINT_MAX_LEN] = {0};
    va_list arg;
    int ret;

    if (module >= SOFTBUS_LOG_MODULE_MAX || level >= SOFTBUS_LOG_LEVEL_MAX) {
        HILOG_ERROR(LOG_CORE, "[COMM]softbus log type or module error");
        return;
    }

    ret = sprintf_s(szStr, sizeof(szStr), "[%s]", g_logInfo[module].name);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "[COMM]softbus log error");
        return;
    }
    ulPos = strlen(szStr);
    (void)memset_s(&arg, sizeof(va_list), 0, sizeof(va_list));
    va_start(arg, fmt);
    ret = vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, fmt, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_ERROR(LOG_CORE, "[COMM]softbus log len error");
        return;
    }
    SoftBusOutPrint(szStr, level);

    return;
}
