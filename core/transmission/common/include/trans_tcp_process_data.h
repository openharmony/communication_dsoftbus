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

#ifndef TRANS_TCP_PROCESS_DATA_H
#define TRANS_TCP_PROCESS_DATA_H

#include <stdint.h>

#include "common_list.h"
#include "softbus_adapter_socket.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "trans_assemble_tlv.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAGIC_NUMBER 0xBABEFACE
#define DC_DATA_HEAD_SIZE 16

typedef struct {
    ListNode node;
    int32_t channelId;
    int32_t fd;
    uint32_t size;
    char *data;
    char *w;
} DataBuf;

typedef struct {
    uint32_t magicNumber;
    int32_t seq;
    uint32_t flags;
    uint32_t dataLen;
} __attribute__((packed)) TcpDataPacketHead;

typedef struct {
    uint32_t magicNumber;
    uint8_t tlvCount;
    int32_t seq;
    uint32_t dataSeq;
    uint32_t flags;
    uint32_t dataLen;
    bool needAck;
} __attribute__((packed)) TcpDataTlvPacketHead;

typedef struct {
    uint32_t outLen;
    uint32_t tlvHeadLen;
} DataLenInfo;

typedef struct {
    bool needAck;
    bool supportTlv;
    int32_t seq;
    uint32_t len;
} TransTdcPackDataInfo;

typedef struct {
    const char *in;
    uint32_t inLen;
    char *out;
    uint32_t *outLen;
} EncrptyInfo;

int32_t TransTdcRecvFirstData(int32_t channelId, char *recvBuf, int32_t *recvLen, int32_t fd, size_t len);
int32_t TransTdcRecvMtpMsg(int32_t channelId, int32_t fd, SoftBusMsgHdr *msg, int32_t *recvLen);
int32_t TransTdcUnPackAllData(int32_t channelId, DataBuf *node, bool *flag);
int32_t TransTdcUnPackData(int32_t channelId, const char *sessionKey, char *plain, uint32_t *plainLen, DataBuf *node);
int32_t TransTdcUnPackAllTlvData(
    int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *newDataHeadSize, DataBuf *node, bool *flag);
int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen);
int32_t MoveNode(int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize);
int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf);
int32_t TransGetTdcDataBufMaxSize(void);
uint32_t TransGetDataBufSize(void);
char *TransTdcPackAllData(
    TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo);
int32_t BuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize);
int32_t BuildDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flags, uint32_t dataLen, int32_t *tlvBuffersize);
char *TransTdcPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen);
void ReleaseDataHeadResource(DataHead *pktHead);
int32_t TransTdcEncryptWithSeq(const char *sessionKey, int32_t seqNum, EncrptyInfo *info);
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_TCP_PROCESS_DATA_H

