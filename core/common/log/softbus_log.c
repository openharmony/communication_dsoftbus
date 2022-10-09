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
#include "softbus_utils.h"

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
#define INLEN_MULTIPLE_FACTOR 2

#define PLAINTEXT_LEN_SHORT 1
#define PLAINTEXT_LEN_NORMAL 4
#define ANONYMIZE_LEN 6
#define SHORT_ID_LENGTH 20
#define SESSION_NAME_DEVICE_ID_LEN 96
#define SESSION_NAME_DEVICE_PATTERN "([0-9A-Z]{32}){1,3}"
#define CUST_NSTACKX_DFINDER_LOG 5

static int32_t g_logLevel;

typedef struct {
    SoftBusLogModule mod;
    char name[LOG_NAME_MAX_LEN];
} LogInfo;

typedef enum {
    ANONYMIZE_NORMAL = 1,
    ANONYMIZE_ENHANCE
} AnonymizeMode;

static LogInfo g_logInfo[SOFTBUS_LOG_MODULE_MAX] = {
    {SOFTBUS_LOG_AUTH, "AUTH"},
    {SOFTBUS_LOG_TRAN, "TRAN"},
    {SOFTBUS_LOG_CONN, "CONN"},
    {SOFTBUS_LOG_LNN, "LNN"},
    {SOFTBUS_LOG_DISC, "DISC"},
    {SOFTBUS_LOG_COMM, "COMM"},
};

void NstackxLog(const char *moduleName, uint32_t nstackLevel, const char *format, ...)
{
    uint32_t ulPos;
    uint32_t level = CUST_NSTACKX_DFINDER_LOG - nstackLevel;
    char szStr[LOG_PRINT_MAX_LEN] = {0};
    va_list arg;
    int32_t ret;

    if (moduleName == NULL || level >= SOFTBUS_LOG_LEVEL_MAX) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Nstackx log moduleName or level error");
        return;
    }

    SoftbusGetConfig(SOFTBUS_INT_ADAPTER_LOG_LEVEL, (unsigned char *)&g_logLevel, sizeof(g_logLevel));
    if ((int32_t)level < g_logLevel) {
        return;
    }

    ret = sprintf_s(szStr, sizeof(szStr), "[%s]", moduleName);
    if (ret < 0) {
        HILOG_ERROR(SOFTBUS_HILOG_ID, "Nstackx log error");
        return;
    }
    ulPos = strlen(szStr);
    (void)memset_s(&arg, sizeof(va_list), 0, sizeof(va_list));
    va_start(arg, format);
    ret = vsprintf_s(&szStr[ulPos], sizeof(szStr) - ulPos, format, arg);
    va_end(arg);
    if (ret < 0) {
        HILOG_WARN(SOFTBUS_HILOG_ID, "Nstackx log len error");
        return;
    }
    SoftBusOutPrint(szStr, (SoftBusLogLevel)level);

    return;
}

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

static int32_t AnonymizeRegInit(regex_t *preg, const char *pattern)
{
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

static int32_t AnonymizeStringProcess(char *str, size_t len, AnonymizeMode mode)
{
    if (len < ANONYMIZE_LEN || mode == ANONYMIZE_ENHANCE) {
        if (strcpy_s(str, len, "******") != EOK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: strncpy fail.");
            return SOFTBUS_MEM_ERR;
        }
    } else {
        uint32_t plaintextLen = len < SHORT_ID_LENGTH ? PLAINTEXT_LEN_SHORT : PLAINTEXT_LEN_NORMAL;
        if (memset_s(str + plaintextLen, len - plaintextLen, '*', ANONYMIZE_LEN) != EOK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: memset fail.");
            return SOFTBUS_MEM_ERR;
        }
        uint32_t offset = plaintextLen + ANONYMIZE_LEN;
        if (strncpy_s(str + offset, len - offset, str + len - plaintextLen, plaintextLen) != EOK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: strncpy fail.");
            return SOFTBUS_MEM_ERR;
        }
    }
    return SOFTBUS_OK;
}

static int32_t AnonymizeString(char **output, const char *in, size_t inLen, const char *pattern, AnonymizeMode mode)
{
    if (in == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: in is null");
        return SOFTBUS_INVALID_PARAM;
    }

    char *str = (char *)SoftBusCalloc(inLen + 1);
    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: malloc fail.");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(str, inLen + 1, in) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: strcpy fail.");
        SoftBusFree(str);
        return SOFTBUS_MEM_ERR;
    }
    regex_t preg;
    if (AnonymizeRegInit(&preg, pattern) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: init reg failed.");
        SoftBusFree(str);
        return SOFTBUS_ERR;
    }
    regmatch_t pmatch[PMATCH_SIZE];
    (void)memset_s(pmatch, sizeof(regmatch_t) * PMATCH_SIZE, 0, sizeof(regmatch_t) * PMATCH_SIZE);
    char *outexec = str;
    do {
        if (regexec(&preg, outexec, PMATCH_SIZE, pmatch, 0) != 0) {
            break;
        }
        regoff_t start = pmatch[0].rm_so;
        regoff_t end = pmatch[0].rm_eo;
        if (start != end) {
            if (AnonymizeStringProcess(outexec + start, end - start, mode) != SOFTBUS_OK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymizeStringProcess fail");
                SoftBusFree(str);
                AnonymizeRegDeinit(&preg);
                return SOFTBUS_ERR;
            }
            int32_t offset = start + (int32_t)strlen(outexec + start);
            char tmpStr[inLen + 1];
            if (strcpy_s(tmpStr, inLen + 1, outexec + end) != EOK || strcat_s(str, inLen, tmpStr) != EOK) {
                SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize string: strcat fail.");
                break;
            }
            outexec += offset;
        }
    } while (true);
    *output = str;
    AnonymizeRegDeinit(&preg);
    return SOFTBUS_OK;
}

void AnonyPacketPrintout(SoftBusLogModule module, const char *msg, const char *packet, size_t packetLen)
{
    if (!GetSignalingMsgSwitch()) {
        return;
    }
    if (msg == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: msg is null.");
        return;
    }
    if (packet == NULL || packetLen == 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: packet is null.");
        return;
    }
    if (packetLen > LOG_PRINT_MAX_LEN * INLEN_MULTIPLE_FACTOR) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: packet is too long.");
        return;
    }

#ifdef __LITEOS_M__
    SoftBusLog(module, SOFTBUS_LOG_INFO, "%s******", msg);
#else
    char pattern[REG_PATTERN_MAX_LEN] = {0};
    if (sprintf_s(pattern, REG_PATTERN_MAX_LEN, "%s|%s|%s|%s|%s",
        REG_ID_PATTERN, REG_IDT_PATTERN, REG_IP_PATTERN, REG_MAC_PATTERN, REG_KEY_PATTERN) < 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anonymize packet: concatenate reg pattern fail");
        return;
    }
    char *anonymizedOut = NULL;
    int32_t ret = AnonymizeString(&anonymizedOut, packet, packetLen, pattern, ANONYMIZE_NORMAL);
    if (ret == SOFTBUS_OK) {
        SoftBusLog(module, SOFTBUS_LOG_INFO, "%s%s", msg, anonymizedOut);
        SoftBusFree(anonymizedOut);
    }
#endif
}

const char *AnonyDevId(char **outName, const char *inName)
{
    if (inName == NULL) {
        return "null";
    }
    if (strlen(inName) < SESSION_NAME_DEVICE_ID_LEN) {
        return inName;
    }
#ifdef __LITEOS_M__
    return "******";
#else
    if (AnonymizeString(outName, inName, strlen(inName), SESSION_NAME_DEVICE_PATTERN, ANONYMIZE_NORMAL) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "anony sessionname fail.");
        return "******";
    }
    return *outName;
#endif
}
