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

#include <regex.h>
#include <securec.h>
#include <stdbool.h>
#include <string.h>

#include "comm_log.h"

#define REG_OK              0
#define MATCH_SIZE          2
#define REG_PATTERN_MAX_LEN 256
#define REG_ID_PATTERN      "[0-9A-Za-z]{64}"
#define REG_IDT_PATTERN     "\\\"[0-9A-Za-z]{32}\\\""
#define REG_IP_PATTERN      "[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}"
#define REG_MAC_PATTERN     "([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}"
#define REG_KEY_PATTERN     "[0-9A-Za-z+-//]{43}="

#define WILDCARD "*"
static const char *ANONYMIZE_WILDCARD = WILDCARD;

static void AnonymizedString(char **anonymizedStr, size_t length, const char *fmt, ...)
{
    va_list args;
    if (memset_s(&args, sizeof(va_list), 0, sizeof(va_list)) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s args fail");
        return;
    }
    *anonymizedStr = (char *)malloc(length);
    if (*anonymizedStr == NULL) {
        COMM_LOGE(COMM_DFX, "malloc str fail");
        return;
    }
    va_start(args, fmt);
    if (vsprintf_s(*anonymizedStr, length, fmt, args) < 0) {
        COMM_LOGE(COMM_DFX, "vsprintf_s *anonymizedStr fail");
    }
    va_end(args);
}

// Replace the first half with ANONYMIZE_WILDCARD and keep the second half.
void Anonymize(const char *plainStr, char **anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    if (plainStr == NULL) {
        const char *retStr = "NULL";
        AnonymizedString(anonymizedStr, strlen(retStr) + 1, "%s", retStr);
        return;
    }
    size_t len = strlen(plainStr);
    if (len < 2) {
        const char *retStr = WILDCARD;
        AnonymizedString(anonymizedStr, strlen(retStr) + 1, "%s", retStr);
        return;
    }
    size_t wildcardLen = strlen(ANONYMIZE_WILDCARD);
    size_t plaintextLen = len / 2;
    size_t plaintextOffset = len - plaintextLen;
    size_t outStrLen = wildcardLen + plaintextLen;
    AnonymizedString(anonymizedStr, outStrLen + 1, "%s%s", ANONYMIZE_WILDCARD, (plainStr + plaintextOffset));
}

#ifndef __LITEOS_M__
static bool CopyString(char **dest, const char *src, size_t length)
{
    *dest = (char *)malloc(length + 1);
    if (dest == NULL) {
        COMM_LOGE(COMM_DFX, "malloc dest fail");
        return false;
    }
    if (strncpy_s(*dest, length + 1, src, length) != EOK) {
        COMM_LOGE(COMM_DFX, "strncpy_s dest fail");
        return false;
    }
    return true;
}

static bool InitAnonymizedStr(char **anonymizedStr)
{
    *anonymizedStr = (char *)malloc(LOG_LINE_MAX_LENGTH + 1);
    if (*anonymizedStr == NULL) {
        COMM_LOGE(COMM_DFX, "malloc *anonymizedStr fail");
        return false;
    }
    if (memset_s(*anonymizedStr, LOG_LINE_MAX_LENGTH + 1, 0, LOG_LINE_MAX_LENGTH + 1) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s *anonymizedStr fail");
        return false;
    }
    return true;
}

static bool ConcatString(char **dest, char *src)
{
    size_t len = strlen(*dest) + strlen(src);
    if (sprintf_s(*dest, len + 1, "%s%s", *dest, src) < 0) {
        COMM_LOGE(COMM_DFX, "sprintf_s *dest fail");
        return false;
    }
    return true;
}

static void AnonymizeRegexp(const char *plainStr, const char *pattern, char **anonymizedStr)
{
    if ((plainStr == NULL) || (pattern == NULL) || (anonymizedStr == NULL)) {
        COMM_LOGW(COMM_DFX, "plainStr or pattern or anonymizedStr is null");
        return;
    }
    char *str;
    if (!CopyString(&str, plainStr, strlen(plainStr))) {
        COMM_LOGE(COMM_DFX, "copy str fail");
        free(str);
        return;
    }

    regex_t reg;
    if (regcomp(&reg, pattern, REG_EXTENDED) != REG_OK) {
        COMM_LOGE(COMM_DFX, "compile reg pattern fail");
        free(str);
        regfree(&reg);
        return;
    }
    regmatch_t match[MATCH_SIZE];
    if (memset_s(match, sizeof(regmatch_t) * MATCH_SIZE, 0, sizeof(regmatch_t) * MATCH_SIZE) != EOK) {
        COMM_LOGE(COMM_DFX, "memset match fail");
        free(str);
        regfree(&reg);
        return;
    }
    if (!InitAnonymizedStr(anonymizedStr)) {
        COMM_LOGE(COMM_DFX, "init anonymizedStr fail");
        free(str);
        regfree(&reg);
        return;
    }
    char *pStr = str;
    do {
        if (regexec(&reg, pStr, MATCH_SIZE, match, 0) != REG_OK) {
            ConcatString(anonymizedStr, pStr);
            break;
        }
        regoff_t start = match[0].rm_so;
        regoff_t end = match[0].rm_eo;
        if (start != end) {
            if (start != 0) {
                char *tempStr;
                if (!CopyString(&tempStr, pStr, start) || !ConcatString(anonymizedStr, tempStr)) {
                    COMM_LOGE(COMM_DFX, "concat *anonymizedStr fail, start=%d", start);
                    free(tempStr);
                    break;
                }
                free(tempStr);
            }
            char *partPlainStr;
            if (!CopyString(&partPlainStr, pStr + start, end - start)) {
                COMM_LOGE(COMM_DFX, "copy partPlainStr fail, start=%d, end=%d", start, end);
                free(partPlainStr);
                break;
            }
            char *tempAnonStr;
            Anonymize(partPlainStr, &tempAnonStr);
            if (tempAnonStr == NULL) {
                COMM_LOGE(COMM_DFX, "tempAnonStr is NULL");
                free(partPlainStr);
                break;
            }
            size_t len = strlen(*anonymizedStr) + strlen(tempAnonStr);
            if (sprintf_s(*anonymizedStr, len + 1, "%s%s", *anonymizedStr, tempAnonStr) < 0) {
                COMM_LOGE(COMM_DFX, "sprintf_s *anonymizedStr fail, len=%d, tempAnonStr=%s", len, tempAnonStr);
                free(partPlainStr);
                AnonymizeFree(tempAnonStr);
                break;
            }
            free(partPlainStr);
            AnonymizeFree(tempAnonStr);
            pStr += end;
        }
    } while (true);
    free(str);
    regfree(&reg);
}

void AnonymizePacket(const char *packet, char **anonymizedStr)
{
    if ((packet == NULL) || (anonymizedStr == NULL)) {
        COMM_LOGW(COMM_DFX, "packet or anonymizedStr is null");
        return;
    }
    size_t packetLen = strlen(packet);
    if (packetLen > LOG_LINE_MAX_LENGTH) {
        // print log only, no need to return
        COMM_LOGW(COMM_DFX, "packet is too long, may lose some context, length=%zu", packetLen);
    }
    char pattern[REG_PATTERN_MAX_LEN] = { 0 };
    (void)sprintf_s(pattern, REG_PATTERN_MAX_LEN, "%s|%s|%s|%s|%s", REG_ID_PATTERN, REG_IDT_PATTERN, REG_IP_PATTERN,
        REG_MAC_PATTERN, REG_KEY_PATTERN);
    AnonymizeRegexp(packet, pattern, anonymizedStr);
}
#endif // __LITEOS_M__

void AnonymizeFree(char *anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    free(anonymizedStr);
}