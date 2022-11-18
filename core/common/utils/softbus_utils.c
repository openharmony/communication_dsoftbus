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

#include <ctype.h>
#include <stdlib.h>

#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

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

static void *g_timerId = NULL;
static TimerFunCallback g_timerFunList[SOFTBUS_MAX_TIMER_FUN_NUM] = {0};
static bool g_signalingMsgSwitch = false;

SoftBusList *CreateSoftBusList(void)
{
    SoftBusList *list = (SoftBusList *)SoftBusMalloc(sizeof(SoftBusList));
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed");
        return NULL;
    }
    (void)memset_s(list, sizeof(SoftBusList), 0, sizeof(SoftBusList));

    SoftBusMutexAttr mutexAttr;
    mutexAttr.type = SOFTBUS_MUTEX_RECURSIVE;
    if (SoftBusMutexInit(&list->lock, &mutexAttr) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "init lock failed");
        SoftBusFree(list);
        return NULL;
    }

    ListInit(&list->list);
    return list;
}

void DestroySoftBusList(SoftBusList *list)
{
    ListDelInit(&list->list);
    SoftBusMutexDestroy(&list->lock);
    SoftBusFree(list);
    return;
}

int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback)
{
    if (callback == NULL || timerFunId >= SOFTBUS_MAX_TIMER_FUN_NUM ||
        timerFunId < SOFTBUS_CONN_TIMER_FUN) {
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
    if (g_timerId != NULL) {
        return SOFTBUS_OK;
    }
    SetTimerFunc(HandleTimeoutFun);
    g_timerId = SoftBusCreateTimer(&g_timerId, TIMER_TYPE_PERIOD);
    if (SoftBusStartTimer(g_timerId, TIMER_TIMEOUT) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "start timer failed.");
        (void)SoftBusDeleteTimer(g_timerId);
        g_timerId = NULL;
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

void SoftBusTimerDeInit(void)
{
    if (g_timerId != NULL) {
        (void)SoftBusDeleteTimer(g_timerId);
        g_timerId = NULL;
    }
}

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, uint32_t inLen)
{
    (void)outBufLen;

    if ((outBuf == NULL) || (inBuf == NULL) || (inLen % HEXIFY_UNIT_LEN != 0)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return SOFTBUS_ERR;
    }

    uint32_t outLen = UN_HEXIFY_LEN(inLen);
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
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HexToString Error! %c", c);
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
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "HexToString Error! %c2", c2);
            return SOFTBUS_ERR;
        }

        *outBuf++ = (c << HEX_MAX_BIT_NUM) | c2;
        i++;
    }
    return SOFTBUS_OK;
}

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen)
{
    if ((outBuf == NULL) || (inBuf == NULL) || (outBufLen < HEXIFY_LEN(inLen))) {
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
        SoftBusFree(hexAuthId);
        return SOFTBUS_ERR;
    }

    if (ConvertBytesToHexString(str, len, hexAuthId, hexLen) != SOFTBUS_OK) {
        SoftBusFree(hexAuthId);
        return SOFTBUS_ERR;
    }

    SoftBusFree(hexAuthId);
    return SOFTBUS_OK;
}

bool IsValidString(const char *input, uint32_t maxLen)
{
    if (input == NULL) {
        return false;
    }

    uint32_t len = strlen(input);
    if (len >= maxLen) {
        return false;
    }

    return true;
}

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen)
{
    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    char *tmpMac = (char *)SoftBusMalloc(strMacLen * sizeof(char));
    if (tmpMac == NULL) {
        return SOFTBUS_MALLOC_ERR;
    }
    if (memcpy_s(tmpMac, strMacLen, strMac, strMacLen) != EOK) {
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

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen)
{
    int32_t ret;

    if (strMac == NULL || strMacLen < BT_MAC_LEN || binMac == NULL || binMacLen < BT_ADDR_LEN) {
        return SOFTBUS_INVALID_PARAM;
    }
    ret = snprintf_s(strMac, strMacLen, strMacLen - 1, "%02x:%02x:%02x:%02x:%02x:%02x",
        binMac[MAC_BIT_ZERO], binMac[MAC_BIT_ONE], binMac[MAC_BIT_TWO],
        binMac[MAC_BIT_THREE], binMac[MAC_BIT_FOUR], binMac[MAC_BIT_FIVE]);
    if (ret < 0) {
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static char ToUpperCase(char ch)
{
    if (ch >= 'a' && ch <= 'z') {
        return ch - 'a' + 'A';
    }
    return ch;
}

int32_t StrCmpIgnoreCase(const char *str1, const char *str2)
{
    if (str1 == NULL || str2 == NULL) {
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "intercept signaling msg faile");
        return;
    }

    if (module == SOFTBUS_LOG_DISC) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_INFO, "[signaling]:%s, len:%d, data:%s",
                   distinguish, dataLen, signalingMsgBuf);
    } else if (module == SOFTBUS_LOG_CONN) {
        SoftBusLog(SOFTBUS_LOG_CONN, SOFTBUS_LOG_INFO, "[signaling]:%s, len:%d, data:%s",
                   distinguish, dataLen, signalingMsgBuf);
    }
}

void MacInstead(char *data, uint32_t length, char delimiter)
{
    if (length > MAX_MAC_LEN) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "MacInstead len is invalid");
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
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "IpInstead len is invalid");
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
    if (length > MAX_ID_LEN) {
        SoftBusLog(SOFTBUS_LOG_DISC, SOFTBUS_LOG_ERROR, "IdInstead len is invalid");
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
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "invalid param");
        return;
    }
    if (memcpy_s(container, length, data, length) != EOK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "container memcpy_s failed");
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

int32_t GenerateStrHashAndConvertToHexString(const unsigned char *str, uint32_t len, unsigned char *hashStr,
    uint32_t hashStrLen)
{
    int32_t ret;
    unsigned char hashResult[SHA_256_HASH_LEN] = {0};
    if (hashStrLen < HEXIFY_LEN(len / HEXIFY_UNIT_LEN)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate str hash invalid hashStrLen");
        return SOFTBUS_INVALID_PARAM;
    }
    if (str == NULL) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate str hash invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    ret = SoftBusGenerateStrHash(str, strlen((char *)str) + 1, hashResult);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "generate str hash fail, ret=%d", ret);
        return ret;
    }
    ret = ConvertBytesToHexString((char *)hashStr, hashStrLen, (const unsigned char *)hashResult,
        len / HEXIFY_UNIT_LEN);
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "convert bytes to str hash fail, ret=%d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}