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

#include "anonymizer.h"

#include <stdbool.h>
#include <regex.h>
#include <securec.h>
#include <string.h>

#include "comm_log.h"
#include "softbus_error_code.h"

#define REG_OK              0
#define MATCH_SIZE          2
#define REG_PATTERN_MAX_LEN 256
#define REG_ID_PATTERN      "[0-9A-Za-z]{64}"
#define REG_IDT_PATTERN     "\\\"[0-9A-Za-z]{32}\\\""
#define REG_IP_PATTERN      "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define REG_MAC_PATTERN     "([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
#define REG_KEY_PATTERN     "[0-9A-Za-z+-//]{43}="

#define WILDCARD "*"
const static char *ANONYMIZE_WILDCARD = WILDCARD;

// Replace the first half with ANONYMIZE_WILDCARD and keep the second half.
void Anonymize(const char *plainStr, char **anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    if (plainStr == NULL) {
        *anonymizedStr = "NULL";
        return;
    }
    size_t len = strlen(plainStr);
    if (len < 2) {
        *anonymizedStr = WILDCARD;
        return;
    }
    size_t wildcardLen = strlen(ANONYMIZE_WILDCARD);
    size_t plaintextLen = (len / 2);
    size_t outStrLen = wildcardLen + plaintextLen;
    *anonymizedStr = (char *)malloc(outStrLen);
    if (anonymizedStr == NULL) {
        COMM_LOGD(COMM_DFX, "malloc anonymizedStr fail");
        return;
    }
    (void)sprintf_s(*anonymizedStr, outStrLen, "%s%s", ANONYMIZE_WILDCARD, plainStr + plaintextLen);
}

#ifndef __LITEOS_M__
static int32_t AnonymizeStringProcess(char *str, size_t len)
{
    size_t wildcardLen = strlen(ANONYMIZE_WILDCARD);
    size_t plaintextLen = (len / 2);
    if (memset_s(str + plaintextLen, len - plaintextLen, '*', wildcardLen) != EOK) {
        COMM_LOGD(COMM_DFX, "memset wildcard fail");
        return SOFTBUS_MEM_ERR;
    }
    uint32_t offset = plaintextLen + wildcardLen;
    if (strncpy_s(str + offset, len - offset, str + len - plaintextLen, plaintextLen) != EOK) {
        COMM_LOGD(COMM_DFX, "strncpy plaintext fail");
        return SOFTBUS_MEM_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t AnonymizeRegexp(const char *plainStr, const char *pattern, char **anonymizedStr)
{
    if (plainStr == NULL || pattern == NULL || anonymizedStr == NULL) {
        COMM_LOGD(COMM_DFX, "plainStr or pattern or anonymizedStr is null");
        return SOFTBUS_INVALID_PARAM;
    }
    size_t inLen = strlen(plainStr);
    char *str = (char *)malloc(inLen + 1);
    if (str == NULL) {
        COMM_LOGD(COMM_DFX, "malloc str fail");
        return SOFTBUS_MEM_ERR;
    }
    if (strcpy_s(str, inLen + 1, plainStr) != EOK) {
        COMM_LOGD(COMM_DFX, "strcpy str fail");
        free(str);
        return SOFTBUS_MEM_ERR;
    }
    regex_t reg;
    if (regcomp(&reg, pattern, REG_EXTENDED) != REG_OK) {
        COMM_LOGD(COMM_DFX, "compile reg pattern fail");
        free(str);
        regfree(&reg);
        return SOFTBUS_ERR;
    }
    regmatch_t match[MATCH_SIZE];
    if (memset_s(match, sizeof(regmatch_t) * MATCH_SIZE, 0, sizeof(regmatch_t) * MATCH_SIZE) != EOK) {
        COMM_LOGD(COMM_DFX, "memset match fail");
        free(str);
        regfree(&reg);
        return SOFTBUS_MEM_ERR;
    }
    char *outExec = str;
    do {
        if (regexec(&reg, outExec, MATCH_SIZE, match, 0) != REG_OK) {
            break;
        }
        regoff_t start = match[0].rm_so;
        regoff_t end = match[0].rm_eo;
        if (start != end) {
            if (AnonymizeStringProcess(outExec + start, end - start) != SOFTBUS_OK) {
                free(str);
                regfree(&reg);
                return SOFTBUS_ERR;
            }
            int32_t offset = start + (int32_t)strlen(outExec + start);
            char tmpStr[inLen + 1];
            if (strcpy_s(tmpStr, inLen + 1, outExec + end) != EOK || strcat_s(str, inLen, tmpStr) != EOK) {
                COMM_LOGD(COMM_DFX, "strcpy or strcat fail");
                break;
            }
            outExec += offset;
        }
    } while (true);
    *anonymizedStr = str;
    regfree(&reg);
    return SOFTBUS_OK;
}

void AnonymizePacket(const char *packet, char **anonymizedStr)
{
    if (packet == NULL || anonymizedStr == NULL) {
        COMM_LOGD(COMM_DFX, "packet or anonymizedStr is null");
        return;
    }
    if (strlen(packet) > LOG_LINE_MAX_LENGTH) {
        COMM_LOGD(COMM_DFX, "packet is too long, will lose some context"); // print log only, no need to return
    }
    char pattern[REG_PATTERN_MAX_LEN] = { 0 };
    (void)sprintf_s(pattern, REG_PATTERN_MAX_LEN, "%s|%s|%s|%s|%s", REG_ID_PATTERN, REG_IDT_PATTERN, REG_IP_PATTERN,
        REG_MAC_PATTERN, REG_KEY_PATTERN);
    (void)AnonymizeRegexp(packet, pattern, anonymizedStr);
}
#endif // __LITEOS_M__

void AnonymizeFree(char *anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    free(anonymizedStr);
    anonymizedStr = NULL;
}