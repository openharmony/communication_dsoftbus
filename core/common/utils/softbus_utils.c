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

#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_timer.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_type_def.h"

static void *g_timerId = NULL;
static TimerFunCallback g_timerFunList[SOFTBUS_MAX_TIMER_FUN_NUM] = {0};

SoftBusList *CreateSoftBusList(void)
{
    pthread_mutexattr_t attr;
    SoftBusList *list = (SoftBusList *)SoftBusMalloc(sizeof(SoftBusList));
    if (list == NULL) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "malloc failed");
        return NULL;
    }
    (void)memset_s(list, sizeof(SoftBusList), 0, sizeof(SoftBusList));

    pthread_mutexattr_init(&attr);
    pthread_mutexattr_settype(&attr, PTHREAD_MUTEX_RECURSIVE);
    if (pthread_mutex_init(&list->lock, &attr) != 0) {
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
    pthread_mutex_destroy(&list->lock);
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
    g_timerId = SoftBusCreateTimer(&g_timerId, (void *)HandleTimeoutFun, TIMER_TYPE_PERIOD);
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

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, int32_t inLen)
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

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, int32_t inLen)
{
    if ((outBuf == NULL) || (inBuf == NULL) || (outBufLen < (uint32_t)HEXIFY_LEN(inLen))) {
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
    if ((len == 0) || (len >= maxLen)) {
        return false;
    }

    return true;
}
