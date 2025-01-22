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

#ifndef SOFTBUS_UTILS_H
#define SOFTBUS_UTILS_H

#include "softbus_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

#define HEXIFY_UNIT_LEN 2
#define UN_HEXIFY_LEN(len) ((len) / HEXIFY_UNIT_LEN)
#define HEXIFY_LEN(len) ((len) * HEXIFY_UNIT_LEN + 1)
#define HEX_MAX_NUM 16
#define DEC_MAX_NUM 10
#define HEX_MAX_BIT_NUM 4
#define MAX_QUERY_LEN 64
#define INT64_TO_STR_MAX_LEN 21

#define TIMER_TIMEOUT 1000 // 1s
#define BT_MAC_NO_COLON_LEN 13
#define TRANS_CAPABILITY_TLV_OFFSET 0
#define TRANS_CHANNEL_CAPABILITY 0x01

#define MAC_DELIMITER ':'
#define IP_DELIMITER '.'
#define ID_DELIMITER ' '

typedef void (*TimerFunCallback)(void);

typedef enum {
    SOFTBUS_CONN_TIMER_FUN,
    SOFTBUS_AUTHEN_TIMER_FUN,
    SOFTBUS_SESSION_TIMER_FUN,
    SOFTBUS_PROXYCHANNEL_TIMER_FUN,
    SOFTBUS_PROXYSLICE_TIMER_FUN,
    SOFTBUS_TCP_DIRECTCHANNEL_TIMER_FUN,
    SOFTBUS_UDP_CHANNEL_TIMER_FUN,
    SOFTBUS_TIME_SYNC_TIMER_FUN,
    SOFTBUS_PROXY_SENDFILE_TIMER_FUN,
    SOFTBUS_NIP_NODE_AGING_TIMER_FUN,
    SOFTBUS_TRNAS_IDLE_TIMEOUT_TIMER_FUN,
    SOFTBUS_TRNAS_REQUEST_TIMEOUT_TIMER_FUN,
    SOFTBUS_TRANS_ASYNC_SENDBYTES_TIMER_FUN,
    SOFTBUS_MAX_TIMER_FUN_NUM
} SoftBusTimerFunEnum;

int32_t RegisterTimeoutCallback(int32_t timerFunId, TimerFunCallback callback);

int32_t SoftBusTimerInit(void);

void SoftBusTimerDeInit(void);
SoftBusList *CreateSoftBusList(void);

void DestroySoftBusList(SoftBusList *list);

int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf, uint32_t inLen);

int32_t ConvertBtMacToStrNoColon(char *strMac, uint32_t strMacLen, const uint8_t *binMac,
    uint32_t binMacLen);

int32_t ConvertHexStringToBytes(unsigned char *outBuf, uint32_t outBufLen, const char *inBuf, uint32_t inLen);

int32_t ConvertBytesToUpperCaseHexString(char *outBuf, uint32_t outBufLen,
    const unsigned char *inBuf, uint32_t inLen);

int32_t GenerateRandomStr(char *str, uint32_t size);

bool IsValidString(const char *input, uint32_t maxLen);

int32_t ConvertBtMacToBinary(const char *strMac, uint32_t strMacLen, uint8_t *binMac, uint32_t binMacLen);

int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen);

int32_t ConvertReverseBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen);

int32_t ConvertBtMacToU64(const char *strMac, uint32_t strMacLen, uint64_t *u64Mac);

int32_t ConvertU64MacToStr(uint64_t u64Mac, char *strMac, uint32_t strMacLen);

bool Int64ToString(int64_t src, char *buf, uint32_t bufLen);
int32_t StrCmpIgnoreCase(const char *str1, const char *str2);

int32_t StringToUpperCase(const char *str, char *buf, int32_t size);

int32_t StringToLowerCase(const char *str, char *buf, int32_t size);

int32_t WriteInt32ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t data);

int32_t WriteUint8ToBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t data);

int32_t ReadInt32FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, int32_t *data);

int32_t ReadUint8FromBuf(uint8_t *buf, uint32_t dataLen, int32_t *offSet, uint8_t *data);

void SetSignalingMsgSwitchOn(void);
void SetSignalingMsgSwitchOff(void);
bool GetSignalingMsgSwitch(void);

/**
 * @brief Intercept signaling messages of specified length and print.
 * @param[in] distinguish Distinguish the sending and receiving of ble, COAP and P2P signaling messages.
 * @param[in] data Signaling message.
 * @param[in] dataLen Length of the signaling message.
 * @param[in] module softbus log module.
 */
void SignalingMsgPrint(const char *distinguish, unsigned char *data, unsigned char dataLen, uint32_t module);

void DataMasking(const char *data, uint32_t length, char delimiter, char *container);
int32_t GenerateStrHashAndConvertToHexString(const unsigned char *str, uint32_t len, unsigned char *hashStr,
    uint32_t hashStrLen);

void EnableCapabilityBit(uint32_t *value, uint32_t offSet);

bool GetCapabilityBit(uint32_t *value, uint32_t offSet);
#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif /* SOFTBUS_UTILS_H */