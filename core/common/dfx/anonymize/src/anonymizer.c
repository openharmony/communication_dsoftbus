/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#include <locale.h>
#include <securec.h>
#include <stdbool.h>
#include <stdint.h>
#include <wchar.h>

#include "comm_log.h"
#include "softbus_error_code.h"

#define DEVICE_NAME_MAX_LEN 128
#define WIDE_CHAR_MAX_LEN 8

typedef struct {
    bool (*Matcher)(const char *, uint32_t);
    int32_t (*Anonymizer)(const char *, uint32_t, char **);
} AnonymizeHandler;

static const char SYMBOL_ANONYMIZE = '*';
static const char SYMBOL_COLON = ':';
static const char SYMBOL_DASH = '-';
static const char SYMBOL_DOT = '.';

static inline bool InRange(char chr, char left, char right)
{
    return left <= chr && chr <= right;
}

static inline bool IsNum(char chr)
{
    return InRange(chr, '0', '9');
}

static inline bool IsHex(char chr)
{
    return IsNum(chr) || InRange(chr, 'A', 'F') || InRange(chr, 'a', 'f');
}

static inline bool IsAlphabet(char chr)
{
    return InRange(chr, 'A', 'Z') || InRange(chr, 'a', 'z');
}

static inline bool IsDot(char chr)
{
    return chr == SYMBOL_DOT;
}

static inline bool IsColon(char chr)
{
    return chr == SYMBOL_COLON;
}

static inline bool IsDash(char chr)
{
    return chr == SYMBOL_DASH;
}

static inline int32_t FindChar(char chr, const char *str, uint32_t len, uint32_t startPos)
{
    for (uint32_t i = startPos; i < len; ++i) {
        if (str[i] == chr) {
            return (int32_t)i;
        }
    }
    return -1; // not find
}

static bool IsValid(const char *str, const uint32_t *positions, uint32_t positionNum, bool(*isValidFunc)(char))
{
    for (uint32_t i = 0; i < positionNum; ++i) {
        if (!isValidFunc(str[positions[i]])) {
            return false;
        }
    }
    return true;
}

static bool MatchEmpty(const char *str, uint32_t len)
{
    (void)str;
    return len == 0;
}

static bool MatchIpAddr(const char *str, uint32_t len)
{
    static const uint32_t DOT_NUM_MAX = 3;
    static const int32_t NUM_LEN_MAX = 3;
    static const int32_t NUM_LEN_MIN = 1;
    static const uint32_t IP_ADDR_MAX_LEN = 15;

    if (len > IP_ADDR_MAX_LEN) {
        return false;
    }

    for (uint32_t i = 0; i < len; ++i) {
        if (!IsNum(str[i]) && !IsDot(str[i])) {
            return false;
        }
    }

    int32_t numLen = 0;
    int32_t posPrevDot = -1;
    int32_t posNextDot = -1;
    for (uint32_t dotNum = 0; dotNum < DOT_NUM_MAX; ++dotNum) {
        posNextDot = FindChar(SYMBOL_DOT, str, len, posPrevDot + 1);
        numLen = posNextDot - posPrevDot - 1;
        if (numLen < NUM_LEN_MIN || numLen > NUM_LEN_MAX) {
            return false;
        }
        posPrevDot = posNextDot;
    }
    numLen = (int32_t)len - posPrevDot - 1;
    if (numLen < NUM_LEN_MIN || numLen > NUM_LEN_MAX) {
        return false;
    }

    return true;
}

static bool MatchMacAddr(const char *str, uint32_t len)
{
    static const uint32_t MAC_ADDR_LEN = 17;
    static const uint32_t DELIMETER_POSITIONS[] = {2, 5, 8, 11, 14};
    static const uint32_t HEX_POSITIONS[] = {0, 1, 3, 4, 6, 7, 9, 10, 12, 13, 15, 16};

    if (len != MAC_ADDR_LEN) {
        return false;
    }

    return IsValid(str, HEX_POSITIONS, sizeof(HEX_POSITIONS) / sizeof(HEX_POSITIONS[0]), IsHex) &&
        (IsValid(str, DELIMETER_POSITIONS, sizeof(DELIMETER_POSITIONS) / sizeof(DELIMETER_POSITIONS[0]), IsDash) ||
        IsValid(str, DELIMETER_POSITIONS, sizeof(DELIMETER_POSITIONS) / sizeof(DELIMETER_POSITIONS[0]), IsColon));
}

static bool MatchUdidStr(const char *str, uint32_t len)
{
    const uint32_t UDID_LEN = 64;

    if (len != UDID_LEN) {
        return false;
    }
    for (uint32_t i = 0; i < len; ++i) {
        if (!IsNum(str[i]) && !IsAlphabet(str[i])) {
            return false;
        }
    }
    return true;
}

static bool MatchDeviceName(const char *str, uint32_t len)
{
    return len <= DEVICE_NAME_MAX_LEN;
}

static char *MallocStr(uint32_t len)
{
    char *str = (char *)malloc(sizeof(char) * (len + 1));
    if (str != NULL) {
        str[len] = '\0';
    }
    return str;
}

static int32_t CopyStr(const char *str, char **copy)
{
    uint32_t len = strlen(str);
    *copy = MallocStr(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(*copy != NULL, SOFTBUS_MALLOC_ERR, COMM_DFX, "malloc failed");

    errno_t ret = memcpy_s(*copy, len, str, len);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_DFX, "memcpy failed");

    return SOFTBUS_OK;
}

static int32_t AnonymizeIpAddr(const char *str, uint32_t len, char **anonymized)
{
    int32_t ret = CopyStr(str, anonymized);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_DFX, "copy ip addr failed");

    for (uint32_t i = len - 1; i >= 0; --i) {
        if (IsDot((*anonymized)[i])) {
            break;
        }
        (*anonymized)[i] = SYMBOL_ANONYMIZE;
    }
    return SOFTBUS_OK;
}

static int32_t AnonymizeMacAddr(const char *str, uint32_t len, char **anonymized)
{
    static const uint32_t ANONYMIZE_POSITIONS[] = {9, 10, 12, 13};

    int32_t ret = CopyStr(str, anonymized);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_DFX, "copy mac addr failed");

    for (uint32_t i = 0; i < sizeof(ANONYMIZE_POSITIONS) / sizeof(ANONYMIZE_POSITIONS[0]); ++i) {
        (*anonymized)[ANONYMIZE_POSITIONS[i]] = SYMBOL_ANONYMIZE;
    }
    return SOFTBUS_OK;
}

static int32_t AnonymizeUdidStr(const char *str, uint32_t len, char **anonymized)
{
    static const uint32_t ANONYMIZE_UDID_LEN = 12;
    static const uint32_t ANONYMIZE_POSITIONS[] = {5, 6};
    static const uint32_t UNANONYMIZE_UDID_LEN = 5;
    static const uint32_t UNANONYMIZE_SUFFIX_POS = ANONYMIZE_UDID_LEN - UNANONYMIZE_UDID_LEN;
    static const uint32_t UNANONYMIZE_SUFFIX_OFFSET = 64 - UNANONYMIZE_UDID_LEN;

    (void)len;
    *anonymized = MallocStr(ANONYMIZE_UDID_LEN);
    COMM_CHECK_AND_RETURN_RET_LOGE(*anonymized != NULL, SOFTBUS_MALLOC_ERR, COMM_DFX, "malloc failed");

    errno_t ret = memcpy_s(*anonymized, ANONYMIZE_UDID_LEN, str, UNANONYMIZE_UDID_LEN);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_DFX, "memcpy failed");
    ret = memcpy_s(*anonymized + UNANONYMIZE_SUFFIX_POS, ANONYMIZE_UDID_LEN - UNANONYMIZE_SUFFIX_POS,
        str + UNANONYMIZE_SUFFIX_OFFSET, UNANONYMIZE_UDID_LEN);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_DFX, "memcpy failed");

    for (uint32_t i = 0; i < sizeof(ANONYMIZE_POSITIONS) / sizeof(ANONYMIZE_POSITIONS[0]); ++i) {
        (*anonymized)[ANONYMIZE_POSITIONS[i]] = SYMBOL_ANONYMIZE;
    }
    return SOFTBUS_OK;
}

static int32_t SetLocale(char **localeBefore)
{
    *localeBefore = setlocale(LC_CTYPE, NULL);
    if (*localeBefore == NULL) {
        COMM_LOGW(COMM_DFX, "get locale failed");
    }

    char *localeAfter = setlocale(LC_CTYPE, "C.UTF-8");
    return (localeAfter != NULL) ? SOFTBUS_OK : SOFTBUS_LOCALE_ERR;
}

static void RestoreLocale(const char *localeBefore)
{
    if (setlocale(LC_CTYPE, localeBefore) == NULL) {
        COMM_LOGW(COMM_DFX, "restore locale failed");
    }
}

static int32_t AnonymizeMultiByteStr(const char *str, uint32_t len, uint32_t lenRatio, uint32_t posRatio,
    char **anonymized)
{
    COMM_CHECK_AND_RETURN_RET_LOGE(lenRatio != 0, SOFTBUS_INVALID_PARAM, COMM_DFX, "lenRatio is 0");
    COMM_CHECK_AND_RETURN_RET_LOGE(posRatio != 0, SOFTBUS_INVALID_PARAM, COMM_DFX, "posRatio is 0");

    wchar_t wideStr[DEVICE_NAME_MAX_LEN] = {0};
    size_t wideCharNum = mbstowcs(wideStr, str, len);
    if (wideCharNum == 0 || wideCharNum > len) {
        COMM_LOGW(COMM_DFX, "convert wide str failed");
        return CopyStr(str, anonymized);
    }

    *anonymized = MallocStr(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(*anonymized != NULL, SOFTBUS_MALLOC_ERR, COMM_DFX, "malloc failed");

    uint32_t wideStrLen = (uint32_t)wideCharNum;
    uint32_t anonymizedNum = (wideStrLen + lenRatio - 1) / lenRatio; // +ratio-1 for round up
    uint32_t plainPrefixPos = wideStrLen / posRatio;
    uint32_t plainSuffixPos = plainPrefixPos + anonymizedNum;

    char multiByteChar[WIDE_CHAR_MAX_LEN] = {0};
    uint32_t multiByteStrIndex = 0;
    uint32_t wideStrIndex = 0;
    errno_t ret = EOK;
    for (; wideStrIndex < plainPrefixPos && multiByteStrIndex < len; ++wideStrIndex) {
        int32_t multiByteCharLen = wctomb(multiByteChar, wideStr[wideStrIndex]);
        COMM_CHECK_AND_RETURN_RET_LOGE(multiByteCharLen > 0, SOFTBUS_WIDECHAR_ERR, COMM_DFX, "convert prefix failed");
        ret = memcpy_s(*anonymized + multiByteStrIndex, len - multiByteStrIndex, multiByteChar, multiByteCharLen);
        COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, COMM_DFX, "copy prefix failed");
        multiByteStrIndex += (uint32_t)multiByteCharLen;
    }

    for (; wideStrIndex < plainSuffixPos && multiByteStrIndex < len; ++wideStrIndex) {
        (*anonymized)[multiByteStrIndex++] = SYMBOL_ANONYMIZE;
    }

    for (; wideStrIndex < wideStrLen && multiByteStrIndex < len; ++wideStrIndex) {
        int32_t multiByteCharLen = wctomb(multiByteChar, wideStr[wideStrIndex]);
        COMM_CHECK_AND_RETURN_RET_LOGE(multiByteCharLen > 0, SOFTBUS_WIDECHAR_ERR, COMM_DFX, "convert suffix failed");
        ret = memcpy_s(*anonymized + multiByteStrIndex, len - multiByteStrIndex, multiByteChar, multiByteCharLen);
        COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, COMM_DFX, "copy prefix failed");
        multiByteStrIndex += (uint32_t)multiByteCharLen;
    }

    uint32_t endPos = multiByteStrIndex < len ? multiByteStrIndex : len;
    (*anonymized)[endPos] = '\0';
    return SOFTBUS_OK;
}

static int32_t AnonymizeDeviceName(const char *str, uint32_t len, char **anonymized)
{
    static const uint32_t ANONYMIZE_LEN_RATIO = 2; // anonymize half str
    static const uint32_t ANONYMIZE_POS_RATIO = 4; // start from 1/4 pos

    char *localeBefore = NULL;
    int32_t ret = SetLocale(&localeBefore);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_DFX, "get locale failed");

    ret = AnonymizeMultiByteStr(str, len, ANONYMIZE_LEN_RATIO, ANONYMIZE_POS_RATIO, anonymized);
    RestoreLocale(localeBefore);
    COMM_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, COMM_DFX, "anonymize multi byte str failed");
    return ret;
}

static int32_t AnonymizeHalfStr(const char *str, uint32_t len, char **anonymized)
{
    uint32_t plainTextLen = len / 2;
    uint32_t plainTextOffset = len - plainTextLen;
    uint32_t anonymizeLen = 1 + plainTextLen;

    *anonymized = MallocStr(anonymizeLen);
    COMM_CHECK_AND_RETURN_RET_LOGE(*anonymized != NULL, SOFTBUS_MALLOC_ERR, COMM_DFX, "malloc failed");

    if (plainTextLen > 0) {
        errno_t ret = memcpy_s(*anonymized + 1, plainTextLen, str + plainTextOffset, plainTextLen);
        COMM_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, COMM_DFX, "memcpy failed");
    }

    (*anonymized)[0] = SYMBOL_ANONYMIZE;
    return SOFTBUS_OK;
}

static int32_t AnonymizeEmpty(const char *str, uint32_t len, char **anonymized)
{
    (void)str;
    (void)len;
    return CopyStr("EMPTY", anonymized);
}

static int32_t AnonymizeInner(const char *str, char **anonymized)
{
    if (str == NULL) {
        return CopyStr("NULL", anonymized);
    }

    static const AnonymizeHandler ANONYMIZE_HANDLER[] = {
        { MatchEmpty, AnonymizeEmpty },
        { MatchIpAddr, AnonymizeIpAddr },
        { MatchMacAddr, AnonymizeMacAddr },
        { MatchUdidStr, AnonymizeUdidStr },
        { MatchDeviceName, AnonymizeDeviceName },
    };

    uint32_t len = strlen(str);
    for (uint32_t i = 0; i < sizeof(ANONYMIZE_HANDLER) / sizeof(AnonymizeHandler); ++i) {
        if (ANONYMIZE_HANDLER[i].Matcher(str, len)) {
            return ANONYMIZE_HANDLER[i].Anonymizer(str, len, anonymized);
        }
    }
    return AnonymizeHalfStr(str, len, anonymized);
}

void Anonymize(const char *plainStr, char **anonymizedStr)
{
    COMM_CHECK_AND_RETURN_LOGE(anonymizedStr != NULL, COMM_DFX, "anonymizedStr is null");

    if (AnonymizeInner(plainStr, anonymizedStr) == SOFTBUS_OK) {
        return;
    }
    if (*anonymizedStr != NULL) {
        AnonymizeFree(*anonymizedStr);
        *anonymizedStr = NULL;
    }
}

void AnonymizeFree(char *anonymizedStr)
{
    if (anonymizedStr == NULL) {
        return;
    }
    free(anonymizedStr);
}

const char *AnonymizeWrapper(const char *anonymizedStr)
{
    return anonymizedStr ? anonymizedStr : "NULL";
}
