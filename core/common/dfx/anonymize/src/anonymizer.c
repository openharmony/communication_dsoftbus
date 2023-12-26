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

#include <securec.h>
#include <string.h>

#include "comm_log.h"

#ifndef __LITEOS_M__
#include <regex.h>

#define REG_OK           0
#define REG_NOK          (-1)
#define MATCH_SIZE       2
#define REG_UDID_PATTERN "^[0-9A-Za-z]{64}$"
#define REG_MAC_PATTERN  "^([0-9A-Fa-f]{2}[:-]){5}[0-9A-Fa-f]{2}$"
#define REG_IP_PATTERN   "^[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}$"
#endif // __LITEOS_M__

#define WILDCARD "*"
static const char *ANONYMIZE_WILDCARD = WILDCARD;

#ifndef __LITEOS_M__
static int32_t AnonymizeMatch(const char *plainStr, const char *pattern)
{
    regex_t reg;
    if (regcomp(&reg, pattern, REG_EXTENDED) != REG_OK) {
        COMM_LOGE(COMM_DFX, "regcomp pattern fail");
        return REG_NOK;
    }
    regmatch_t match[MATCH_SIZE] = { 0 };
    if (regexec(&reg, plainStr, MATCH_SIZE, match, 0) != REG_OK) {
        COMM_LOGD(COMM_DFX, "regexec pattern not match");
        regfree(&reg);
        return REG_NOK;
    }
    regfree(&reg);
    return REG_OK;
}

static void AnonymizeUdid(const char *udid, char **anonymizedUdid)
{
    const size_t ANONYMIZED_UDID_LEN = 12;
    *anonymizedUdid = (char *)malloc(ANONYMIZED_UDID_LEN + 1);
    if (*anonymizedUdid == NULL) {
        COMM_LOGE(COMM_DFX, "malloc *anonymizedStr fail");
        return;
    }
    if (memset_s(*anonymizedUdid, ANONYMIZED_UDID_LEN + 1, 0, ANONYMIZED_UDID_LEN + 1) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s *anonymizedStr fail");
        return;
    }
    // Reserve 5 chars at head, concat with two wildcards, and 5 chars at tail
    const size_t RESERVED_LEN = 5;
    const char *WILDCARDS = "**";
    if (strncpy_s(*anonymizedUdid, ANONYMIZED_UDID_LEN + 1, udid, RESERVED_LEN) != EOK ||
        strcpy_s((*anonymizedUdid + RESERVED_LEN), (ANONYMIZED_UDID_LEN - RESERVED_LEN + 1), WILDCARDS) != EOK ||
        strncpy_s((*anonymizedUdid + RESERVED_LEN + strlen(WILDCARDS)),
            (ANONYMIZED_UDID_LEN - RESERVED_LEN - strlen(WILDCARDS) + 1), (udid + strlen(udid) - RESERVED_LEN),
            RESERVED_LEN) != EOK) {
        COMM_LOGE(COMM_DFX, "strncpy_s *anonymizedUdid fail");
    }
}

static void AnonymizeMac(const char *mac, char **anonymizedMac)
{
    size_t anonymizedMacLen = strlen(mac);
    *anonymizedMac = (char *)malloc(anonymizedMacLen + 1);
    if (*anonymizedMac == NULL) {
        COMM_LOGE(COMM_DFX, "malloc *anonymizedMac fail");
        return;
    }
    if (memset_s(*anonymizedMac, anonymizedMacLen + 1, 0, anonymizedMacLen + 1) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s *anonymizedStr fail");
        return;
    }
    if (strcpy_s(*anonymizedMac, anonymizedMacLen + 1, mac) != EOK) {
        COMM_LOGE(COMM_DFX, "strcpy_s *anonymizedMac fail");
        return;
    }
    // Anonymize the forth and fifth parts of the mac address
    (*anonymizedMac)[9] = '*';
    (*anonymizedMac)[10] = '*';
    (*anonymizedMac)[12] = '*';
    (*anonymizedMac)[13] = '*';
}

static void AnonymizeIp(const char *ip, char **anonymizedIp)
{
    size_t anonymizedIpLen = strlen(ip);
    *anonymizedIp = (char *)malloc(anonymizedIpLen + 1);
    if (*anonymizedIp == NULL) {
        COMM_LOGE(COMM_DFX, "malloc *anonymizedIp fail");
        return;
    }
    if (memset_s(*anonymizedIp, anonymizedIpLen + 1, 0, anonymizedIpLen + 1) != EOK) {
        COMM_LOGE(COMM_DFX, "memset_s *anonymizedIp fail");
        return;
    }
    if (strcpy_s(*anonymizedIp, anonymizedIpLen + 1, ip) != EOK) {
        COMM_LOGE(COMM_DFX, "strcpy_s *anonymizedIp fail");
        return;
    }
    // Anonymize the last part of ip address
    size_t index = anonymizedIpLen - 1;
    while ((*anonymizedIp)[index] != '.') {
        (*anonymizedIp)[index] = '*';
        --index;
    }
}

static int32_t AnonymizeRegexp(const char *plainStr, char **anonymizedStr)
{
    if (AnonymizeMatch(plainStr, REG_UDID_PATTERN) == REG_OK) {
        AnonymizeUdid(plainStr, anonymizedStr);
        return REG_OK;
    }
    if (AnonymizeMatch(plainStr, REG_MAC_PATTERN) == REG_OK) {
        AnonymizeMac(plainStr, anonymizedStr);
        return REG_OK;
    }
    if (AnonymizeMatch(plainStr, REG_IP_PATTERN) == REG_OK) {
        AnonymizeIp(plainStr, anonymizedStr);
        return REG_OK;
    }
    return REG_NOK;
}
#endif // __LITEOS_M__

static void AnonymizeString(char **anonymizedStr, size_t length, const char *fmt, ...)
{
    va_list args = { 0 };
    *anonymizedStr = (char *)malloc(length);
    if (*anonymizedStr == NULL) {
        COMM_LOGE(COMM_DFX, "malloc *anonymizedStr fail");
        return;
    }
    va_start(args, fmt);
    int ret = vsprintf_s(*anonymizedStr, length, fmt, args);
    va_end(args);
    if (ret < 0) {
        COMM_LOGE(COMM_DFX, "vsprintf_s *anonymizedStr fail");
    }
}

void Anonymize(const char *plainStr, char **anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    if (plainStr == NULL) {
        const char *retStr = "NULL";
        AnonymizeString(anonymizedStr, strlen(retStr) + 1, "%s", retStr);
        return;
    }
    size_t len = strlen(plainStr);
    if (len == 0) {
        const char *retStr = "EMPTY";
        AnonymizeString(anonymizedStr, strlen(retStr) + 1, "%s", retStr);
        return;
    }
    if (len < 2) {
        const char *retStr = WILDCARD;
        AnonymizeString(anonymizedStr, strlen(retStr) + 1, "%s", retStr);
        return;
    }

#ifndef __LITEOS_M__
    if (AnonymizeRegexp(plainStr, anonymizedStr) == REG_OK) {
        return;
    }
#endif // __LITEOS_M__

    // Replace the first half with one WILDCARD and keep the second half.
    size_t wildcardLen = strlen(ANONYMIZE_WILDCARD);
    size_t plaintextLen = len / 2;
    size_t plaintextOffset = len - plaintextLen;
    size_t outStrLen = wildcardLen + plaintextLen;
    AnonymizeString(anonymizedStr, outStrLen + 1, "%s%s", ANONYMIZE_WILDCARD, (plainStr + plaintextOffset));
}

void AnonymizeFree(char *anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    free(anonymizedStr);
}