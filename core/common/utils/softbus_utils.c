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

#include "softbus_utils.h"

#include <stdlib.h>

#include "comm_log.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_error_code.h"


#define MAC_BIT_ZERO 0
#define MAC_BIT_ONE 1
#define MAC_BIT_TWO 2
#define MAC_BIT_THREE 3
#define MAC_BIT_FOUR 4
#define MAC_BIT_FIVE 5

#define BT_ADDR_LEN 6
#define BT_ADDR_DELIMITER ":"
#define BT_ADDR_BASE 16

#define BUF_BYTE_LEN 64
#define BUF_HEX_LEN 128
#define OFFSET 1

#define MAC_DELIMITER_SECOND 2
#define MAC_DELIMITER_FOURTH 4
#define IP_DELIMITER_FIRST 1
#define IP_DELIMITER_THIRD 3
#define GET_ID_HALF_LEN 2
#define MAX_ID_LEN 65
#define MAX_IP_LEN 48
#define MAX_MAC_LEN 46
#define MAX_HANDLE_TIMES 3600

#define ONE_BYTE_SIZE 8

#ifdef SOFTBUS_STANDARD_OS
static int32_t *g_timerHandle = NULL;
#else
static void *g_timerId = NULL;
#endif
static TimerFunCallback g_timerFunList[SOFTBUS_MAX_TIMER_FUN_NUM] = {0};
static bool g_signalingMsgSwitch = false;

SoftBusList *CreateSoftBusList(void)
{
    SoftBusList *list = (SoftBusList *)SoftBusMalloc(sizeof(SoftBusList));
    if (list == NULL) {
        COMM_LOGE(COMM_UTILS, "malloc failed");
        return NULL;
    }
    (void)memset_s(list, sizeof(SoftBusList), 0, sizeof(SoftBusList));

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&list->lock, &mutexAttr) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "init lock failed");
        SoftBusFree(list);
        return NULL;
    }
    ListInit(&list->list);
    return list;
}

void DestroySoftBusList(SoftBusList *list)
{
    if (list == NULL) {
        COMM_LOGE(COMM_UTILS, "list is null");
        return;
    }
    ListDelInit(&list->list);
    SoftBusMutexDestroy(&list->lock);
    SoftBusFree(list);
    return;
}

int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback)
{
    if (callback == NULL || timerFunId >= SOFTBUS_MAX_TIMER_FUN_NUM ||
        timerFunId < SOFTBUS_CONN_TIMER_FUN) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_ERR;
    }
    if (g_timerFunList[timerFunId] != NULL) {
        return SOFTBUS_OK;
    }
    g_timerFunList[timerFunId] = callback;
    return SOFTBUS_OK;
}

static void HandleTimeoutFun(void)
{
    int32_t i;
    for (i = 0; i < SOFTBUS_MAX_TIMER_FUN_NUM; i++) {
        if (g_timerFunList[i] != NULL) {
            g_timerFunList[i]();
        }
    }
}

int32_t SoftBusTimerInit(void)
{
#ifdef SOFTBUS_STANDARD_OS
    if (g_timerHandle != NULL) {
        return SOFTBUS_OK;
    }
    SetTimerFunc(HandleTimeoutFun);
    g_timerHandle = (int32_t *)SoftBusCalloc(sizeof(int32_t));
    if (g_timerHandle == NULL) {
        COMM_LOGE(COMM_UTILS, "timerHandle calloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    int32_t ret = SoftBusStartTimerWithFfrt(g_timerHandle, TIMER_TIMEOUT, true);
    if (ret != SOFTBUS_OK) {
        SoftBusFree(g_timerHandle);
        g_timerHandle = NULL;
        COMM_LOGE(COMM_UTILS, "softbus timer init fail, ret=%{public}d", ret);
    }
    return ret;
#else
    if (g_timerId != NULL) {
        return SOFTBUS_OK;
    }
    SetTimerFunc(HandleTimeoutFun);
    g_timerId = SoftBusCreateTimer(&g_timerId, TIMER_TYPE_PERIOD);
    if (SoftBusStartTimer(g_timerId, TIMER_TIMEOUT) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "start timer failed.");
        (void)SoftBusDeleteTimer(g_timerId);
        g_timerId = NULL;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
#endif
}

void SoftBusTimerDeInit(void)
{
#ifdef SOFTBUS_STANDARD_OS
    if (g_timerHandle != NULL) {
        SoftBusStopTimerWithFfrt(*g_timerHandle);
        SoftBusFree(g_timerHandle);
        g_timerHandle = NULL;
    }
    return;
#else
    if (g_timerId != NULL) {
        (void)SoftBusDeleteTimer(g_timerId);
        g_timerId = NULL;
    }
#endif
}

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen, const unsigned char * inBuf,
    uint32_t inLen)
{
    if ((outBuf == NULL) || (inBuf == NULL) || (outBufLen < HEXIFY_LEN(inLen))) {
        COMM_LOGE(COMM_UTILS, "invalid param, inlen=%{public}u, outBufLen=%{public}u", inLen, outBufLen);
        return SOFTBUS_ERR;
    }

    while (inLen > 0) {
        unsigned char h = *inBuf / HEX_MAX_NUM;
        unsigned char l = *inBuf % HEX_MAX_NUM;
        if (h < DEC_MAX_NUM) {
            *outBuf++ = '0' + h;
        } else {
            *outBuf++ = 'A' + h - DEC_MAX_NUM;
        }
        if (l < DEC_MAX_NUM) {
            *outBuf++ = '0' + l;
        } else {
            *outBuf++ = 'A' + l - DEC_MAX_NUM;
        }
        ++inBuf;
        inLen--;
    }
    return SOFTBUS_OK;
}

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf,
    uint32_t inLen)
{
    if ((outBuf == NULL) || (inBuf == NULL) || (inLen % HEXIFY_UNIT_LEN != 0)) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t outLen = UN_HEXIFY_LEN(inLen);
    if (outLen > outBufLen) {
        COMM_LOGE(COMM_UTILS, "outLen > outBufLen");
        return SOFTBUS_ERR;
    }
    uint32_t i = 0;
    while (i < outLen) {
        unsigned char c = *inBuf++;
        if ((c >= '0') && (c <= '9')) {
            c -= '0';
        } else if ((c >= 'a') && (c <= 'f')) {
            c -= 'a' - DEC_MAX_NUM;
        } else if ((c >= 'A') && (c <= 'F')) {
            c -= 'A' - DEC_MAX_NUM;
        } else {
            COMM_LOGE(COMM_UTILS, "HexToString Error! inBuf=%{public}c", c);
            return SOFTBUS_ERR;
        }
        unsigned char c2 = *inBuf++;
        if ((c2 >= '0') && (c2 <= '9')) {
            c2 -= '0';
        } else if ((c2 >= 'a') && (c2 <= 'f')) {
            c2 -= 'a' - DEC_MAX_NUM;
        } else if ((c2 >= 'A') && (c2 <= 'F')) {
            c2 -= 'A' - DEC_MAX_NUM;
        } else {
            COMM_LOGE(COMM_UTILS, "HexToString Error! inBuf2=%{public}c", c2);
            return SOFTBUS_ERR;
        }
        *outBuf++ = (c << HEX_MAX_BIT_NUM) | c2;
        i++;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
    uint32_t inLen)
{
    if ((outBuf == NULL) || (inBuf == NULL) || (outBufLen < HEXIFY_LEN(inLen))) {
        COMM_LOGD(COMM_UTILS, "outBufLen=%{public}d, inLen=%{public}d", outBufLen, inLen);
        return SOFTBUS_ERR;
    }

    while (inLen > 0) {
        unsigned char h = *inBuf / HEX_MAX_NUM;
        unsigned char l = *inBuf % HEX_MAX_NUM;
        if (h < DEC_MAX_NUM) {
            *outBuf++ = '0' + h;
        } else {
            *outBuf++ = 'a' + h - DEC_MAX_NUM;
        }
        if (l < DEC_MAX_NUM) {
            *outBuf++ = '0' + l;
        } else {
            *outBuf++ = 'a' + l - DEC_MAX_NUM;
        }
        ++inBuf;
        inLen--;
    }
    return SOFTBUS_OK;
}

int32_t GenerateRandomStr(char *str, uint32_t len)
{
    if ((str == NULL) ||  (len < HEXIFY_UNIT_LEN)) {
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t hexLen = len / HEXIFY_UNIT_LEN;
    unsigned char *hexAuthId = (unsigned char *)SoftBusMalloc(hexLen);
    if (hexAuthId == NULL) {
        return SOFTBUS_MEM_ERR;
    }
    (void)memset_s(hexAuthId, hexLen, 0, hexLen);
    if (SoftBusGenerateRandomArray(hexAuthId, hexLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "Generate random array fail");
        SoftBusFree(hexAuthId);
        return SOFTBUS_ERR;
    }
    if (ConvertBytesToHexString(str, len, hexAuthId, hexLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "Convert bytes to hexstring fail");
        SoftBusFree(hexAuthId);
        return SOFTBUS_ERR;
    }
    SoftBusFree(hexAuthId);
    return SOFTBUS_OK;
}

bool IsValidString(const char *input, uint32_t maxLen)
{
    if (input == NULL) {
        COMM_LOGE(COMM_UTILS, "input is null");
        return false;
    }
    uint32_t len = strlen(input);
    if (len == 0 || len > maxLen) {
        return false;
    }
    return true;
}

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac,
    uint32_t binMacLen)
{
    const char *invalidAddr = "00:00:00:00:00:00";
    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN ||
        strncmp(strMac, invalidAddr, BT_MAC_LEN) == 0) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpMac = (char *)SoftBusMalloc(strMacLen * sizeof(char));
    if (tmpMac == NULL) {
        COMM_LOGE(COMM_UTILS, "tmpMac is null");
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(tmpMac, strMacLen, strMac, strMacLen) != EOK) {
        COMM_LOGE(COMM_UTILS, "memcpy tmpMac fail");
        SoftBusFree(tmpMac);
        return SOFTBUS_MEM_ERR;
    }
    char *nextTokenPtr = NULL;
    char *token = strtok_r((char *)tmpMac, BT_ADDR_DELIMITER, &nextTokenPtr);
    char *endptr = NULL;
    for (int i = 0; i < BT_ADDR_LEN; i++) {
        if (token == NULL) {
            SoftBusFree(tmpMac);
            return SOFTBUS_ERR;
        }
        binMac[i] = strtoul(token, &endptr, BT_ADDR_BASE);
        token = strtok_r(NULL, BT_ADDR_DELIMITER, &nextTokenPtr);
    }
    SoftBusFree(tmpMac);
    return SOFTBUS_OK;
}

int32_t ConvertBtMacToStrNoColon(char *strMac, uint32_t strMacLen, const uint8_t *binMac,
    uint32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_NO_COLON_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x%02x%02x%02x%02x%02x",
        binMac[MAC_BIT_ZERO], binMac[MAC_BIT_ONE], binMac[MAC_BIT_TWO],
        binMac[MAC_BIT_THREE], binMac[MAC_BIT_FOUR], binMac[MAC_BIT_FIVE]);
    if (ret < 0) {
        COMM_LOGE(COMM_UTILS, "snprintf_s fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac,
    uint32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        binMac[MAC_BIT_ZERO], binMac[MAC_BIT_ONE], binMac[MAC_BIT_TWO],
        binMac[MAC_BIT_THREE], binMac[MAC_BIT_FOUR], binMac[MAC_BIT_FIVE]);
    if (ret < 0) {
        COMM_LOGE(COMM_UTILS, "snprintf_s fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConvertReverseBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    int32_t ret;
    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        binMac[MAC_BIT_FIVE], binMac[MAC_BIT_FOUR], binMac[MAC_BIT_THREE],
        binMac[MAC_BIT_TWO], binMac[MAC_BIT_ONE], binMac[MAC_BIT_ZERO]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBtMacToU64(const char *strMac, uint32_t strMacLen, uint64_t *u64Mac)
{
    if (strMac == NULL || strMacLen < BT_MAC_LEN || u64Mac == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };
    int32_t status = ConvertBtMacToBinary(strMac, BT_MAC_LEN, binaryAddr, BT_ADDR_LEN);
    if (status != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "Convert btMac to binary fail");
        return SOFTBUS_ERR;
    }
    uint64_t u64Value = 0;
    for (int i = 0; i < BT_ADDR_LEN; i++) {
        u64Value = (u64Value << ONE_BYTE_SIZE) | binaryAddr[i];
    }
    *u64Mac = u64Value;
    return SOFTBUS_OK;
}

int32_t ConvertU64MacToStr(uint64_t u64Mac, char *strMac, uint32_t strMacLen)
{
    if (strMac == NULL || strMacLen < BT_MAC_LEN || u64Mac == 0) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint8_t binaryAddr[BT_ADDR_LEN] = { 0 };
    for (int i = BT_ADDR_LEN - 1; i >= 0; i--) {
        binaryAddr[i] = u64Mac & 0xFF;
        u64Mac = u64Mac >> ONE_BYTE_SIZE;
    }
    return ConvertBtMacToStr(strMac, strMacLen, binaryAddr, BT_ADDR_LEN);
}
static char ToUpperCase(char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 'A';
    }
    return ch;
}

static char ToLowerCase(char ch)
{
    if (ch >= 'A' && ch <= 'Z') {
        return ch - 'A' + 'a';
    }
    return ch;
}

int32_t StringToUpperCase(const char *str, char *buf, int32_t size)
{
    if (str == NULL || buf == NULL) {
        return SOFTBUS_ERR;
    }
    memset_s(buf, size, 0, size);
    int32_t i;
    for (i = 0; str[i] != '\0'; i++) {
        buf[i] = ToUpperCase(str[i]);
    }
    return SOFTBUS_OK;
}

int32_t StringToLowerCase(const char *str, char *buf, int32_t size)
{
    if (str == NULL || buf == NULL) {
        return SOFTBUS_ERR;
    }
    memset_s(buf, size, 0, size);
    int32_t i;
    for (i = 0; str[i] != '\0'; i++) {
        buf[i] = ToLowerCase(str[i]);
    }
    return SOFTBUS_OK;
}

bool Int64ToString(int64_t src, char *buf, uint32_t bufLen)
{
    if (buf == NULL) {
        return false;
    }
    if (sprintf_s(buf, bufLen, "%" PRId64"", src) < 0) {
        COMM_LOGE(COMM_UTILS, "convert int64 to str fail");
        return false;
    }
    return true;
}

int32_t StrCmpIgnoreCase(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
        COMM_LOGD(COMM_UTILS, "invalid param");
        return SOFTBUS_ERR;
    }
    int32_t i;
    for (i = 0; str1[i] != '\0' && str2[i] != '\0'; i++) {
        if (ToUpperCase(str1[i]) != ToUpperCase(str2[i])) {
            return SOFTBUS_ERR;
        }
    }
    if (str1[i] != '\0' || str2[i] != '\0') {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SetSignalingMsgSwitchOn(void)
{
    g_signalingMsgSwitch = true;
}

void SetSignalingMsgSwitchOff(void)
{
    g_signalingMsgSwitch = false;
}

bool GetSignalingMsgSwitch(void)
{
    return g_signalingMsgSwitch;
}

void SignalingMsgPrint(const char *distinguish, unsigned char *data, unsigned char dataLen, uint32_t module)
{
    int ret = 0;
    char signalingMsgBuf[BUF_HEX_LEN] = {0};

    if (!GetSignalingMsgSwitch()) {
        return;
    }
    if (dataLen >= BUF_BYTE_LEN) {
        ret = ConvertBytesToHexString(signalingMsgBuf, BUF_HEX_LEN + OFFSET, data, BUF_BYTE_LEN);
    } else {
        ret = ConvertBytesToHexString(signalingMsgBuf, BUF_HEX_LEN + OFFSET, data, dataLen);
    }
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "intercept signaling msg failed");
        return;
    }
}

void MacInstead(char *data, uint32_t length, char delimiter)
{
    if (length > MAX_MAC_LEN) {
        COMM_LOGE(COMM_UTILS, "MacInstead len is invalid");
        return;
    }
    int delimiterCnt = 0;
    for (uint32_t i = 0; i < length; i++) {
        if (delimiterCnt == MAC_DELIMITER_FOURTH) {
            break;
        }
        if (data[i] == delimiter) {
            delimiterCnt++;
        }
        if (delimiterCnt >= MAC_DELIMITER_SECOND && data[i] != delimiter) {
            data[i] = '*';
        }
    }
}

void IpInstead(char *data, uint32_t length, char delimiter)
{
    if (length > MAX_IP_LEN) {
        COMM_LOGE(COMM_UTILS, "IpInstead len is invalid");
        return;
    }
    int delimiterCnt = 0;
    for (uint32_t i = 0; i < length; i++) {
        if (delimiterCnt == IP_DELIMITER_THIRD) {
            break;
        }
        if (data[i] == delimiter) {
            delimiterCnt++;
        }
        if (delimiterCnt >= IP_DELIMITER_FIRST && data[i] != delimiter) {
            data[i] = '*';
        }
    }
}

void IdInstead(char *data, uint32_t length)
{
    if (length < 1 || length > MAX_ID_LEN) {
        COMM_LOGE(COMM_UTILS, "IdInstead len is invalid");
        return;
    }
    uint32_t halfLen = length / GET_ID_HALF_LEN;
    for (uint32_t i = 0; i < length - 1; i++) {
        if (i > halfLen) {
            data[i] = '*';
        }
    }
}

void DataMasking(const char *data, uint32_t length, char delimiter, char *container)
{
    if (data == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return;
    }
    if (memcpy_s(container, length, data, length) != EOK) {
        COMM_LOGE(COMM_UTILS, "container memcpy_s failed");
        return;
    }
    switch (delimiter) {
        case MAC_DELIMITER:
            MacInstead(container, length, delimiter);
            break;
        case IP_DELIMITER:
            IpInstead(container, length, delimiter);
            break;
        case ID_DELIMITER:
            IdInstead(container, length);
            break;
        default:
            break;
    }
}

int32_t GenerateStrHashAndConvertToHexString(const unsigned char *str, uint32_t len,
    unsigned char *hashStr, uint32_t hashStrLen)
{
    int32_t ret;
    unsigned char hashResult[SHA_256_HASH_LEN] = {0};
    if (hashStrLen < HEXIFY_LEN(len / HEXIFY_UNIT_LEN)) {
        COMM_LOGE(COMM_UTILS, "generate str hash invalid hashStrLen");
        return SOFTBUS_INVALID_PARAM;
    }
    if (str == NULL) {
        COMM_LOGE(COMM_UTILS, "generate str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str), hashResult);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "generate str hash fail, ret=%{public}d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString((char *)hashStr, hashStrLen, (const unsigned char *)hashResult,
        len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_UTILS, "convert bytes to str hash fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t checkParamIsNull(uint8_t *buf, int32_t *offSet)
{
    if (buf == NULL) {
        COMM_LOGE(COMM_UTILS, "param buf is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (offSet == NULL) {
        COMM_LOGE(COMM_UTILS, "param offSet is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    return SOFTBUS_OK;
}

int32_t WriteInt32ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t data)
{
    int32_t ret = checkParamIsNull(buf, offSet);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (dataLen < *offSet + sizeof(data)) {
        COMM_LOGE(COMM_UTILS, "write data is long than dataLen!");
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *((int32_t *)(buf + *offSet)) = data;
    *offSet += sizeof(data);
    return SOFTBUS_OK;
}

int32_t WriteUint8ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t data)
{
    int32_t ret = checkParamIsNull(buf, offSet);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (dataLen < *offSet + sizeof(data)) {
        COMM_LOGE(COMM_UTILS, "write data is long than dataLen!");
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *(buf + *offSet) = data;
    *offSet += sizeof(data);
    return SOFTBUS_OK;
}


int32_t ReadInt32FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t *data)
{
    int32_t ret = checkParamIsNull(buf, offSet);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (data == NULL) {
        COMM_LOGE(COMM_UTILS, "param data is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen < *offSet + sizeof(*data)) {
        COMM_LOGE(COMM_UTILS, "Read data is long than dataLen!");
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *data = *((int32_t *)(buf + *offSet));
    *offSet += sizeof(*data);
    return SOFTBUS_OK;
}

int32_t ReadUint8FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t *data)
{
    int32_t ret = checkParamIsNull(buf, offSet);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (data == NULL) {
        COMM_LOGE(COMM_UTILS, "param data is NULL");
        return SOFTBUS_INVALID_PARAM;
    }
    if (dataLen < *offSet + sizeof(*data)) {
        COMM_LOGE(COMM_UTILS, "Read data is long than dataLen!");
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    *data = *(buf + *offSet);
    *offSet += sizeof(*data);
    return SOFTBUS_OK;
}

void EnableCapabilityBit(uint32_t *value, uint32_t offSet)
{
    if (value == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return;
    }
    *value |= (1 << offSet);
}

bool GetCapabilityBit(uint32_t *value, uint32_t offSet)
{
    if (value == NULL) {
        COMM_LOGE(COMM_UTILS, "invalid param");
        return false;
    }
    return (bool)((*value >> offSet) & 0x1);
}