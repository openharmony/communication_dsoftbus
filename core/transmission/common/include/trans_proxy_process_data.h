/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef TRANS_PROXY_PROCESS_DATA_H
#define TRANS_PROXY_PROCESS_DATA_H

#include <stdint.h>

#include "common_list.h"
#include "softbus_app_info.h"
#include "softbus_def.h"

#ifdef __cplusplus
extern "C" {
#endif
#ifndef MAGIC_NUMBER
#define MAGIC_NUMBER 0xBABEFACE

#define NONCE_LEN 2
#endif

typedef struct {
    uint8_t *inData;
    uint32_t inLen;
    uint8_t *outData;
    uint32_t outLen;
} ProxyDataInfo;

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} SliceHead;

typedef struct {
    uint16_t sliceNum;
    uint16_t sliceSeq;
} D2dSliceHead;

typedef struct {
    int32_t active;
    int32_t timeout;
    int32_t sliceNumber;
    int32_t expectedSeq;
    int32_t dataLen;
    int32_t bufLen;
    char *data;
    uint64_t timestamp;
} SliceProcessor;

typedef struct {
    int32_t magicNumber;
    int32_t seq;
    int32_t flags;
    int32_t dataLen;
} PacketHead;

typedef struct {
    int32_t flags;
    int32_t dataLen;
} PacketD2DHead;

typedef struct {
    uint8_t flags;
    uint16_t dataLen;
} PacketD2DNewHead;

typedef struct {
    uint16_t nonce;
    uint16_t dataSeq;
} PacketD2DIvSource;

typedef struct {
    uint32_t magicNumber;
    uint8_t tlvCount;
    int32_t seq;
    uint32_t dataSeq;
    uint32_t flags;
    uint32_t dataLen;
    bool needAck;
} DataHeadTlvPacketHead;

typedef enum {
    PROXY_CHANNEL_PRIORITY_MESSAGE = 0,
    PROXY_CHANNEL_PRIORITY_BYTES = 1,
    PROXY_CHANNEL_PRIORITY_FILE = 2,
    PROXY_CHANNEL_PRIORITY_BUTT = 3,
} ProxyChannelPriority;

typedef struct {
    ListNode head;
    int32_t channelId;
    SliceProcessor processor[PROXY_CHANNEL_PRIORITY_BUTT];
} ChannelSliceProcessor;

void TransGetProxyDataBufMaxSize(void);
int32_t TransProxyPackBytes(
    int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq);
int32_t TransProxyPackTlvBytes(
    ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info);
uint8_t *TransProxyPackData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen);
int32_t TransProxyCheckSliceHead(const SliceHead *head);
int32_t TransProxyNoSubPacketProc(PacketHead *head, uint32_t len, const char *data, int32_t channelId);
int32_t TransProxyProcessSessionData(ProxyDataInfo *dataInfo, const PacketHead *dataHead, const char *data);
int32_t TransProxyDecryptPacketData(int32_t seq, ProxyDataInfo *dataInfo, const char *sessionKey);
int32_t TransProxyFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, bool supportTlv);
int32_t TransProxyNormalSliceProcess(SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len);
int32_t TransProxySliceProcessChkPkgIsValid(
    const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len);
void TransProxyClearProcessor(SliceProcessor *processor);
void TransUnPackSliceHead(SliceHead *data);
int32_t TransGetActualDataLen(const SliceHead *head, uint32_t *actualDataLen);
int32_t TransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type);
int32_t TransProxyParseTlv(uint32_t len, const char *data, DataHeadTlvPacketHead *head, uint32_t *headSize);
int32_t TransProxyNoSubPacketTlvProc(
    int32_t channelId, uint32_t len, DataHeadTlvPacketHead *pktHead, uint32_t newPktHeadSize);
int32_t TransProxyProcData(ProxyDataInfo *dataInfo, const DataHeadTlvPacketHead *pktHead, const char *data);

uint8_t *TransProxyPackD2DData(
    ProxyDataInfo *dataInfo, uint32_t sliceNum, SessionPktType pktType, uint32_t cnt, uint32_t *dataLen);
int32_t TransProxyProcessD2DData(ProxyDataInfo *dataInfo, const PacketD2DHead *dataHead,
    const char *data, int32_t businessType);
int32_t TransProxyDecryptD2DData(
    int32_t businessType, ProxyDataInfo *dataInfo, const char *sessionKey, const unsigned char *sessionCommonIv);
int32_t TransProxyD2DFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t businessType);
int32_t TransProxyPackD2DBytes(ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, bool isNewHead);
int32_t TransGenerateToBytesRandIv(unsigned char *sessionIv, const uint32_t *nonce);
uint8_t *TransProxyPackNewHeadD2DData(
    ProxyDataInfo *dataInfo, uint16_t sliceNum, SessionPktType pktType, uint16_t cnt, uint16_t *dataLen);
int32_t TransProxyD2dDataLenCheck(uint32_t dataLen, BusinessType type);
int32_t TransProxyD2DFirstNewHeadSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t businessType);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_PROXY_PROCESS_DATA_H
