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

#include <regex.h>
#include <securec.h>
#include <string.h>

#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_feature_config.h"

#define LOG_NAME_MAX_LEN 5
#ifndef SOFTBUS_DEBUG
#define LOG_PRINT_MAX_LEN 256
#else
#define LOG_PRINT_MAX_LEN 512
#endif

// anonymize should mask more than half of the string
#define EXPECTED_ANONYMIZED_TIMES 2

#define PMATCH_SIZE 2
#define REG_ID_PATTERN "[0-9A-Za-z]{64}"
#define REG_IDT_PATTERN "\\\"[0-9A-Za-z]{32}\\\""
#define REG_IP_PATTERN "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define REG_MAC_PATTERN "([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
#define REG_KEY_PATTERN "[0-9A-Za-z+-//]{43}="
#define REG_PATTERN_MAX_LEN 256
#define REPLACE_DIVISION_BASE 3

static int32_t g_logLevel;

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

void SoftBusLog(SoftBusLogModule module, SoftBusLogLevel level, const char *fmt, ...)
{
    uint32_t ulPos;
    char szStr[LOG_PRINT_MAX_LEN] = {0};
    va_list arg;
    int32_t ret;

    if (module >= SOFTBUS_LOG_MODULE_MAX || level >= SOFTBUS_LOG_LEVEL_MAX) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[COMM]softbus log type or module error");
        return;
    }

    SoftbusGetConfig(SOFTBUS_INT_ADAPTER_LOG_LEVEL, (unsigned char *)&g_logLevel, sizeof(g_logLevel));
    if ((int32_t)level < g_logLevel) {
        return;
    }

    ret = sprintf_s(szStr, sizeof(szStr), "[%s]", g_logInfo[module].name);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "[COMM]softbus log error");
        return;
    }
    ulPos = strlen(szStr);
    (void)memset_s(&arg, sizeof(va_list), 0, sizeof(va_list));
    va_start(arg, fmt);
    ret = vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, fmt, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_WARN(SOFTBUS_HILOG_ID, "[COMM]softbus log len error");
        return;
    }
    SoftBusOutPrint(szStr, level);

    return;
}

const char *Anonymizes(const char *target, const uint8_t expectAnonymizedLength)
{
    if (target == NULL) {
        return "NULL";
    }
    if (expectAnonymizedLength == 0) {
        return "BADLENGTH";
    }
    size_t targetLen = strlen(target);
    if (targetLen / expectAnonymizedLength < EXPECTED_ANONYMIZED_TIMES) {
        return "TOOSHORT";
    }

    return target + (targetLen - expectAnonymizedLength);
}

static int32_t AnonymizeRegInit(regex_t *preg)
{
    char pattern[REG_PATTERN_MAX_LEN] = {0};
    if (sprintf_s(pattern, REG_PATTERN_MAX_LEN, "%s|%s|%s|%s|%s",
        REG_ID_PATTERN, REG_IDT_PATTERN, REG_IP_PATTERN, REG_MAC_PATTERN, REG_KEY_PATTERN) < 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init anonymize reg: concatenate reg pattern fail");
        return SOFTBUS_ERR;
    }
    if (regcomp(preg, pattern, REG_EXTENDED) != 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init anonymize reg: compile reg pattern fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void AnonymizeRegDeinit(regex_t *preg)
{
    regfree(preg);
}

int32_t AnonymizePacket(char **output, const char *in, size_t len)
{
    if (in == NULL || len > LOG_PRINT_MAX_LEN) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: packet is null or too long, len: %d", len);
        return SOFTBUS_INVALID_PARAM;
    }

    regex_t preg;
    if (AnonymizeRegInit(&preg) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: init reg failed.");
        return SOFTBUS_ERR;
    }

    char *str = (char *)SoftBusCalloc(len + 1);
    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: malloc fail.");
        AnonymizeRegDeinit(&preg);
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(str, len + 1, in) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: strcpy fail.");
        SoftBusFree(str);
        AnonymizeRegDeinit(&preg);
        return SOFTBUS_MEM_ERR;
    }

    regmatch_t pmatch[PMATCH_SIZE] = {0};
    char *outexec = str;
    do {
        if (regexec(&preg, outexec, PMATCH_SIZE, pmatch, 0) != 0) {
            break;
        }
        if (pmatch[0].rm_so != pmatch[0].rm_eo) {
            int32_t replaceLen = (pmatch[0].rm_eo - pmatch[0].rm_so) / REPLACE_DIVISION_BASE;
            int32_t offset = pmatch[0].rm_so + replaceLen;
            if (memset_s(outexec + offset, len - offset, '*', replaceLen + 1) != EOK) {
                break;
            }
            outexec += pmatch[0].rm_eo;
        }
    } while (true);
    *output = str;
    AnonymizeRegDeinit(&preg);
    return SOFTBUS_OK;
}
