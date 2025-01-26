/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "client_trans_proxy_manager.h"

#include <securec.h>
#include <unistd.h>

#include "anonymizer.h"
#include "client_trans_assemble_tlv.h"
#include "client_trans_proxy_file_manager.h"
#include "client_trans_session_manager.h"
#include "client_trans_socket_manager.h"
#include "client_trans_tcp_direct_message.h"
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_socket.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_feature_config.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_pending_pkt.h"
#include "trans_server_proxy.h"

#define SLICE_LEN (4 * 1024)
#define PROXY_ACK_SIZE 4
#define OH_TYPE 10
#define PROXY_TLV_ELEMENT 5
#define TLV_TYPE_AND_LENTH 2
#define PROXY_TLV_PKT_HEAD 32
#define MAGICNUM_SIZE sizeof(uint32_t)
#define TLVCOUNT_SIZE sizeof(uint8_t)

static IClientSessionCallBack g_sessionCb;
static uint32_t g_proxyMaxByteBufSize;
static uint32_t g_proxyMaxMessageBufSize;

static SoftBusList *g_proxyChannelInfoList = NULL;
static SoftBusList *g_channelSliceProcessorList = NULL;

typedef struct {
    int32_t priority;
    int32_t sliceNum;
    int32_t sliceSeq;
    int32_t reserved;
} SliceHead;

typedef struct {
    int32_t magicNumber;
    int32_t seq;
    int32_t flags;
    int32_t dataLen;
} PacketHead;

typedef struct {
    uint32_t magicNumber;
    uint8_t tlvCount;
    int32_t seq;
    uint32_t dataSeq;
    uint32_t flags;
    uint32_t dataLen;
    bool needAck;
} DataHeadTlvPacketHead;

typedef struct {
    uint8_t *inData;
    uint32_t inLen;
    uint8_t *outData;
    uint32_t outLen;
} ClientProxyDataInfo;

static int32_t ProxyBuildNeedAckTlvData(DataHead *pktHead, bool needAck, uint32_t dataSeqs, int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid, pktHead is null");
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t dataSeq = SoftBusHtoLl(dataSeqs);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_NEED_ACK, (uint8_t *)&needAck, sizeof(needAck), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "assemble needAck tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_SEQ, (uint8_t *)&dataSeq, sizeof(dataSeq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "assemble dataSeq tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        return ret;
    }
    pktHead->tlvElement -= (PROXY_TLV_ELEMENT * sizeof(TlvElement));
    return SOFTBUS_OK;
}

static int32_t ProxyBuildTlvDataHead(DataHead *pktHead, int32_t finalSeq, int32_t flag, uint32_t dataLen,
    int32_t *tlvBufferSize)
{
    if (pktHead == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    pktHead->tlvElement = (uint8_t *)SoftBusCalloc(PROXY_TLV_ELEMENT * sizeof(TlvElement));
    if (pktHead->tlvElement == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc tlvElement failed");
        return SOFTBUS_MALLOC_ERR;
    }
    pktHead->magicNum = SoftBusHtoLl(MAGIC_NUMBER);
    uint32_t seq = SoftBusHtoLl((uint32_t)finalSeq);
    uint32_t flags = SoftBusHtoLl((uint32_t)flag);
    uint32_t dataLens = SoftBusHtoLl(dataLen);
    int32_t ret = TransAssembleTlvData(pktHead, TLV_TYPE_INNER_SEQ, (uint8_t *)&seq, sizeof(seq), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "assemble seq tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_FLAG, (uint8_t *)&flags, sizeof(flags), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "assemble flag tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        return ret;
    }
    ret = TransAssembleTlvData(pktHead, TLV_TYPE_DATA_LEN, (uint8_t *)&dataLens, sizeof(dataLens), tlvBufferSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "assemble dataLen tlv failed, ret=%{public}d", ret);
        ReleaseTlvValueBuffer(pktHead);
        SoftBusFree(pktHead->tlvElement);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransProxyParseTlv(const char *data, DataHeadTlvPacketHead *head, uint32_t *newDataHeadSize)
{
    if (data == NULL || head == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(&head->magicNumber, MAGICNUM_SIZE, data, MAGICNUM_SIZE) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy magicNumber failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (memcpy_s(&head->tlvCount, TLVCOUNT_SIZE, data + MAGICNUM_SIZE, TLVCOUNT_SIZE) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy tlvCount failed.");
        return SOFTBUS_MEM_ERR;
    }
    *newDataHeadSize += (MAGICNUM_SIZE + TLVCOUNT_SIZE);
    errno_t ret = EOK;
    char *temp = (char *)data + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (uint8_t index = 0; index < head->tlvCount; index++) {
        uint8_t *type = (uint8_t *)temp;
        uint8_t *length = (uint8_t *)(temp + sizeof(uint8_t));
        temp += (TLV_TYPE_AND_LENTH * sizeof(uint8_t));
        switch (*type) {
            case TLV_TYPE_INNER_SEQ:
                ret = memcpy_s(&head->seq, sizeof(head->seq), temp, *length);
                break;
            case TLV_TYPE_DATA_SEQ:
                ret = memcpy_s(&head->dataSeq, sizeof(head->dataSeq), temp, *length);
                break;
            case TLV_TYPE_FLAG:
                ret = memcpy_s(&head->flags, sizeof(head->flags), temp, *length);
                break;
            case TLV_TYPE_NEED_ACK:
                ret = memcpy_s(&head->needAck, sizeof(head->needAck), temp, *length);
                break;
            case TLV_TYPE_DATA_LEN:
                ret = memcpy_s(&head->dataLen, sizeof(head->dataLen), temp, *length);
                break;
            default:
                TRANS_LOGE(TRANS_SDK, "unknown trans tdc tlv skip, tlvType=%{public}d", *type);
                continue;
        }
        temp += *length;
        *newDataHeadSize += (TLV_TYPE_AND_LENTH * sizeof(uint8_t) + *length);
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_MEM_ERR, TRANS_SDK,
            "parse tlv memcpy failed, tlvType=%{public}d, ret=%{public}d", *type, ret);
    }
    return SOFTBUS_OK;
}

void ClientPackSliceHead(SliceHead *data)
{
    data->priority = (int32_t)SoftBusHtoLl((uint32_t)data->priority);
    data->sliceNum = (int32_t)SoftBusHtoLl((uint32_t)data->sliceNum);
    data->sliceSeq = (int32_t)SoftBusHtoLl((uint32_t)data->sliceSeq);
    data->reserved = (int32_t)SoftBusHtoLl((uint32_t)data->reserved);
}

void ClientUnPackSliceHead(SliceHead *data)
{
    data->priority = (int32_t)SoftBusLtoHl((uint32_t)data->priority);
    data->sliceNum = (int32_t)SoftBusLtoHl((uint32_t)data->sliceNum);
    data->sliceSeq = (int32_t)SoftBusLtoHl((uint32_t)data->sliceSeq);
    data->reserved = (int32_t)SoftBusLtoHl((uint32_t)data->reserved);
}

void ClientPackPacketHead(PacketHead *data)
{
    data->magicNumber = (int32_t)SoftBusHtoLl((uint32_t)data->magicNumber);
    data->seq = (int32_t)SoftBusHtoLl((uint32_t)data->seq);
    data->flags = (int32_t)SoftBusHtoLl((uint32_t)data->flags);
    data->dataLen = (int32_t)SoftBusHtoLl((uint32_t)data->dataLen);
}

void ClientUnPackPacketHead(PacketHead *data)
{
    data->magicNumber = (int32_t)SoftBusLtoHl((uint32_t)data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->flags = (int32_t)SoftBusLtoHl((uint32_t)data->flags);
    data->dataLen = (int32_t)SoftBusLtoHl((uint32_t)data->dataLen);
}

void ClientUnPackTlvPackHead(DataHeadTlvPacketHead *data)
{
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "invalid data.");
        return;
    }
    data->magicNumber = SoftBusLtoHl(data->magicNumber);
    data->seq = (int32_t)SoftBusLtoHl((uint32_t)data->seq);
    data->dataSeq = SoftBusLtoHl(data->dataSeq);
    data->flags = SoftBusLtoHl(data->flags);
    data->dataLen = SoftBusLtoHl(data->dataLen);
}

static void ClientTransProxySliceTimerProc(void);

static int32_t ClientTransProxyListInit()
{
    g_proxyChannelInfoList = CreateSoftBusList();
    if (g_proxyChannelInfoList == NULL) {
        return SOFTBUS_NO_INIT;
    }
    g_channelSliceProcessorList = CreateSoftBusList();
    if (g_channelSliceProcessorList == NULL) {
        DestroySoftBusList(g_proxyChannelInfoList);
        return SOFTBUS_NO_INIT;
    }
    if (RegisterTimeoutCallback(SOFTBUS_PROXYSLICE_TIMER_FUN, ClientTransProxySliceTimerProc) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "register timeout fail");
        DestroySoftBusList(g_proxyChannelInfoList);
        DestroySoftBusList(g_channelSliceProcessorList);
        return SOFTBUS_TIMOUT;
    }
    return SOFTBUS_OK;
}

static void ClientTransProxyListDeinit(void)
{
    (void)RegisterTimeoutCallback(SOFTBUS_PROXYSLICE_TIMER_FUN, NULL);
    if (g_proxyChannelInfoList != NULL) {
        DestroySoftBusList(g_proxyChannelInfoList);
        g_proxyChannelInfoList = NULL;
    }
    if (g_channelSliceProcessorList != NULL) {
        DestroySoftBusList(g_channelSliceProcessorList);
        g_channelSliceProcessorList = NULL;
    }
}

int32_t ClientTransProxyInit(const IClientSessionCallBack *cb)
{
    if (cb == NULL) {
        TRANS_LOGE(TRANS_INIT, "param is null!");
        return SOFTBUS_INVALID_PARAM;
    }

    g_sessionCb = *cb;
    if (ClinetTransProxyFileManagerInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClinetTransProxyFileManagerInit init fail!");
        return SOFTBUS_NO_INIT;
    }
    if (ClientTransProxyListInit() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "ClinetTransProxyListInit init fail!");
        return SOFTBUS_NO_INIT;
    }

    if (PendingInit(PENDING_TYPE_PROXY) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "trans proxy pending init failed.");
        return SOFTBUS_NO_INIT;
    }

    if (SoftbusGetConfig(SOFTBUS_INT_MAX_BYTES_NEW_LENGTH, (unsigned char *)&g_proxyMaxByteBufSize,
                         sizeof(g_proxyMaxByteBufSize)) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_INIT, "get auth proxy channel max bytes length fail");
    }
    if (SoftbusGetConfig(SOFTBUS_INT_MAX_MESSAGE_NEW_LENGTH, (unsigned char *)&g_proxyMaxMessageBufSize,
                         sizeof(g_proxyMaxMessageBufSize)) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_INIT, "get auth proxy channel max message length fail");
    }
    TRANS_LOGI(TRANS_INIT, "proxy auth byteSize=%{public}u, messageSize=%{public}u",
        g_proxyMaxByteBufSize, g_proxyMaxMessageBufSize);
    return SOFTBUS_OK;
}

void ClientTransProxyDeinit(void)
{
    ClinetTransProxyFileManagerDeinit();
    PendingDeinit(PENDING_TYPE_PROXY);
    ClientTransProxyListDeinit();
}

int32_t ClientTransProxyGetInfoByChannelId(int32_t channelId, ProxyChannelInfoDetail *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            (void)memcpy_s(info, sizeof(ProxyChannelInfoDetail), &item->detail, sizeof(ProxyChannelInfoDetail));
            item->detail.sequence++;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channel by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

int32_t ClientTransProxyGetOsTypeByChannelId(int32_t channelId, int32_t *osType)
{
    if (osType == NULL || g_proxyChannelInfoList == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            *osType = item->detail.osType;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientTransProxyGetLinkTypeByChannelId(int32_t channelId, int32_t *linkType)
{
    if (linkType == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            *linkType = item->detail.linkType;
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channelId=%{public}d", channelId);
    return SOFTBUS_NOT_FIND;
}

int32_t ClientTransProxyAddChannelInfo(ClientProxyChannelInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "param invalid.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == info->channelId) {
            TRANS_LOGE(TRANS_SDK, "client is existed. channelId=%{public}d", item->channelId);
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }

    ListAdd(&g_proxyChannelInfoList->list, &info->node);
    TRANS_LOGI(TRANS_SDK, "add channelId=%{public}d", info->channelId);
    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    return SOFTBUS_OK;
}

int32_t ClientTransProxyDelChannelInfo(int32_t channelId)
{
    if (SoftBusMutexLock(&g_proxyChannelInfoList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }

    ClientProxyChannelInfo *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &(g_proxyChannelInfoList->list), ClientProxyChannelInfo, node) {
        if (item->channelId == channelId) {
            ListDelete(&item->node);
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(item);
            DelPendingPacket(channelId, PENDING_TYPE_PROXY);
            (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
            return SOFTBUS_OK;
        }
    }

    (void)SoftBusMutexUnlock(&g_proxyChannelInfoList->lock);
    TRANS_LOGE(TRANS_SDK, "can not find proxy channel by channelId=%{public}d", channelId);
    return SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND;
}

static ClientProxyChannelInfo *ClientTransProxyCreateChannelInfo(const ChannelInfo *channel)
{
    ClientProxyChannelInfo *info = (ClientProxyChannelInfo *)SoftBusCalloc(sizeof(ClientProxyChannelInfo));
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "info is null");
        return NULL;
    }
    if (memcpy_s(info->detail.sessionKey, SESSION_KEY_LENGTH, channel->sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusFree(info);
        TRANS_LOGE(TRANS_SDK, "sessionKey memcpy fail");
        return NULL;
    }
    info->channelId = channel->channelId;
    info->detail.isEncrypted = channel->isEncrypt;
    info->detail.sequence = 0;
    info->detail.linkType = channel->linkType;
    info->detail.osType = channel->osType;
    return info;
}

int32_t ClientTransProxyOnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    if (sessionName == NULL || channel == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    ClientProxyChannelInfo *info = ClientTransProxyCreateChannelInfo(channel);
    if (info == NULL) {
        TRANS_LOGE(TRANS_SDK, "create channel info fail, channelId=%{public}d", channel->channelId);
        return SOFTBUS_MEM_ERR;
    }

    int32_t ret = ClientTransProxyAddChannelInfo(info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyAddChannelInfo fail channelId=%{public}d", channel->channelId);
        (void)memset_s(info->detail.sessionKey, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);
        SoftBusFree(info);
        return ret;
    }

    SessionType type = TYPE_BUTT;
    switch (channel->businessType) {
        case BUSINESS_TYPE_BYTE:
            type = TYPE_BYTES;
            break;
        case BUSINESS_TYPE_FILE:
            type = TYPE_FILE;
            break;
        default:
            type = TYPE_MESSAGE;
            break;
    }

    ret = g_sessionCb.OnSessionOpened(sessionName, channel, type);
    if (ret != SOFTBUS_OK) {
        (void)ClientTransProxyDelChannelInfo(channel->channelId);
        char *tmpName = NULL;
        Anonymize(sessionName, &tmpName);
        TRANS_LOGE(TRANS_SDK, "notify session open fail, sessionName=%{public}s.", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId);

int32_t ClientTransProxyOnChannelClosed(int32_t channelId, ShutdownReason reason)
{
    (void)ClientTransProxyDelChannelInfo(channelId);
    (void)TransProxyDelSliceProcessorByChannelId(channelId);

    int ret = g_sessionCb.OnSessionClosed(channelId, CHANNEL_TYPE_PROXY, reason);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session closed errCode=%{public}d, channelId=%{public}d.", ret, channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t ClientTransProxyOnChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    int ret = g_sessionCb.OnSessionOpenFailed(channelId, CHANNEL_TYPE_PROXY, errCode);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify session openfail errCode=%{public}d, channelId=%{public}d.", errCode, channelId);
        return ret;
    }

    return SOFTBUS_OK;
}

int32_t ClientTransProxySessionDataLenCheck(uint32_t dataLen, SessionPktType type)
{
    switch (type) {
        case TRANS_SESSION_MESSAGE:
        case TRANS_SESSION_ASYNC_MESSAGE: {
            if (dataLen > g_proxyMaxMessageBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        case TRANS_SESSION_BYTES: {
            if (dataLen > g_proxyMaxByteBufSize) {
                return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
            }
            break;
        }
        default: {
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyDecryptPacketData(int32_t channelId, int32_t seq, ClientProxyDataInfo *dataInfo)
{
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get channel Info by channelId=%{public}d failed, ret=%{public}d", channelId, ret);
        return ret;
    }
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, info.sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        return SOFTBUS_MEM_ERR;
    }
    ret = SoftBusDecryptDataWithSeq(
        &cipherKey, dataInfo->inData, dataInfo->inLen, dataInfo->outData, &(dataInfo->outLen), seq);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "trans proxy Decrypt Data fail. ret=%{public}d ", ret);
        return SOFTBUS_DECRYPT_ERR;
    }

    return SOFTBUS_OK;
}

static int32_t ClientTransProxyCheckSliceHead(const SliceHead *head)
{
    if (head == NULL) {
        TRANS_LOGW(TRANS_SDK, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (head->priority < 0 || head->priority >= PROXY_CHANNEL_PRORITY_BUTT) {
        TRANS_LOGE(TRANS_SDK, "invalid index=%{public}d", head->priority);
        return SOFTBUS_INVALID_DATA_HEAD;
    }

    if (head->sliceNum != 1 && head->sliceSeq >= head->sliceNum) {
        TRANS_LOGE(TRANS_SDK, "sliceNum=%{public}d, sliceSeq=%{public}d", head->sliceNum, head->sliceSeq);
        return SOFTBUS_INVALID_DATA_HEAD;
    }

    return SOFTBUS_OK;
}

int32_t TransProxyPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType);

static void ClientTransProxySendSessionAck(int32_t channelId, int32_t seq)
{
    unsigned char ack[PROXY_ACK_SIZE] = { 0 };
    int32_t tmpSeq = 0;
    ProxyChannelInfoDetail info;
    if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get proxy info err, channelId=%{public}d", channelId);
        return;
    }
    if (info.osType == OH_TYPE) {
        tmpSeq = (int32_t)SoftBusHtoLl((uint32_t)seq);
    } else {
        tmpSeq = (int32_t)SoftBusHtoNl((uint32_t)seq); // convet host order to net order
    }
    if (memcpy_s(ack, PROXY_ACK_SIZE, &tmpSeq, sizeof(int32_t)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy seq err");
        return;
    }
    info.sequence = seq;
    if (TransProxyPackAndSendData(channelId, ack, PROXY_ACK_SIZE, &info, TRANS_SESSION_ACK) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "send ack err, seq=%{public}d", seq);
    }
}

static int32_t ClientTransProxyProcSendMsgAck(int32_t channelId, const char *data, int32_t len,
                                              int32_t dataHeadSeq, uint32_t dataSeq)
{
    if (len != PROXY_ACK_SIZE) {
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    if (data == NULL) {
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    int32_t seq = *(int32_t *)data;
    int32_t hostSeq = (int32_t)SoftBusNtoHl(*(uint32_t *)data);
    TRANS_LOGI(TRANS_SDK, "channelId=%{public}d, dataHeadSeq=%{public}d, seq=%{public}d, hostSeq=%{public}d",
        channelId, dataHeadSeq, seq, hostSeq);
    if (dataSeq != 0) { // this async process
        int32_t socketId = INVALID_SESSION_ID;
        SessionListenerAdapter sessionCallback;
        bool isServer = false;
        (void)memset_s(&sessionCallback, sizeof(SessionListenerAdapter), 0, sizeof(SessionListenerAdapter));
        int32_t ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get socketId failed, channelId=%{public}d", channelId);
            return ret;
        }
        ret = ClientGetSessionCallbackAdapterById(socketId, &sessionCallback, &isServer);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get session callback failed, channelId=%{public}d", channelId);
            return ret;
        }
        ret = DeleteDataSeqInfoList(dataSeq, channelId);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "proxychannel delete dataSeqInfoList failed, channelId=%{public}d", channelId);
            return ret;
        }
        sessionCallback.socketClient.OnBytesSent(socketId, dataSeq, SOFTBUS_OK);
        return SOFTBUS_OK;
    }
    int32_t ret = SetPendingPacket(channelId, seq, PENDING_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        ret = SetPendingPacket(channelId, hostSeq, PENDING_TYPE_PROXY);
        if (ret == SOFTBUS_OK) {
            TRANS_LOGI(TRANS_SDK, "set pending packet by hostSeq=%{public}d success", hostSeq);
        }
    }
    return ret;
}

static void ClientTransProxySendBytesAck(int32_t channelId, int32_t seq, uint32_t dataSeq, bool needAck)
{
    if (needAck) {
        TRANS_LOGI(TRANS_SDK, "proxy channel server send ack to client");
        unsigned char ack[PROXY_ACK_SIZE] = { 0 };
        int32_t tmpSeq = 0;
        ProxyChannelInfoDetail info;
        if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "get proxy info err, channelId=%{public}d", channelId);
            return;
        }
        if (info.osType == OH_TYPE) {
            tmpSeq = (int32_t)SoftBusHtoLl((uint32_t)seq);
        } else {
            tmpSeq = (int32_t)SoftBusHtoNl((uint32_t)seq);
        }
        if (memcpy_s(ack, PROXY_ACK_SIZE, &tmpSeq, sizeof(int32_t)) != EOK) {
            TRANS_LOGE(TRANS_SDK, "memcpy seq err");
            return;
        }
        info.sequence = seq;
        if (TransProxyAsyncPackAndSendData(channelId, ack, PROXY_ACK_SIZE, dataSeq, TRANS_SESSION_ACK) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "send ack err, seq=%{public}d", seq);
            return;
        }
    }
}

static int32_t ClientTransProxyBytesNotifySession(int32_t channelId, const DataHeadTlvPacketHead *dataHead,
    const char *data, uint32_t len)
{
    SessionPktType flags = (SessionPktType)dataHead->flags;
    int32_t seq = dataHead->seq;
    uint32_t dataSeq = dataHead->dataSeq;
    bool needAck = dataHead->needAck;
    switch (flags) {
        case TRANS_SESSION_MESSAGE:
            ClientTransProxySendSessionAck(channelId, seq);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_ACK:
            return ClientTransProxyProcSendMsgAck(channelId, data, len, seq, dataSeq);
        case TRANS_SESSION_BYTES:
            ClientTransProxySendBytesAck(channelId, seq, dataSeq, needAck);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
        case TRANS_SESSION_ASYNC_MESSAGE:
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        default:
            TRANS_LOGE(TRANS_SDK, "invalid flags=%{public}d", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t ClientTransProxyNotifySession(
    int32_t channelId, SessionPktType flags, int32_t seq, const char *data, uint32_t len)
{
    switch (flags) {
        case TRANS_SESSION_MESSAGE:
            ClientTransProxySendSessionAck(channelId, seq);
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        case TRANS_SESSION_ACK:
            return ClientTransProxyProcSendMsgAck(channelId, data, len, seq, 0);
        case TRANS_SESSION_BYTES:
        case TRANS_SESSION_FILE_FIRST_FRAME:
        case TRANS_SESSION_FILE_ONGOINE_FRAME:
        case TRANS_SESSION_FILE_LAST_FRAME:
        case TRANS_SESSION_FILE_ONLYONE_FRAME:
        case TRANS_SESSION_FILE_ALLFILE_SENT:
        case TRANS_SESSION_FILE_CRC_CHECK_FRAME:
        case TRANS_SESSION_FILE_RESULT_FRAME:
        case TRANS_SESSION_FILE_ACK_REQUEST_SENT:
        case TRANS_SESSION_FILE_ACK_RESPONSE_SENT:
        case TRANS_SESSION_ASYNC_MESSAGE:
            return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, flags);
        default:
            TRANS_LOGE(TRANS_SDK, "invalid flags=%{public}d", flags);
            return SOFTBUS_INVALID_PARAM;
    }
}

static int32_t ClientTransProxyProcessSessionData(int32_t channelId, const PacketHead *dataHead, const char *data)
{
    ClientProxyDataInfo dataInfo = { 0 };
    uint32_t outLen = 0;

    if (dataHead->dataLen <= OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "invalid data head dataLen=%{public}d", dataHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo.outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo.outData == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail when process session out data.");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo.inData = (unsigned char *)data;
    dataInfo.inLen = dataHead->dataLen;
    dataInfo.outLen = outLen;

    int32_t ret = ClientTransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (ClientTransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGD(TRANS_SDK, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    if (ClientTransProxyNotifySession(channelId, (SessionPktType)dataHead->flags, dataHead->seq,
                                      (const char *)dataInfo.outData, dataInfo.outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyProcData(int32_t channelId, const DataHeadTlvPacketHead *dataHead, const char *data)
{
    ClientProxyDataInfo dataInfo = { 0 };
    uint32_t outLen = 0;

    if (dataHead->dataLen <= OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "invalid data head dataLen=%{public}d", dataHead->dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    outLen = dataHead->dataLen - OVERHEAD_LEN;
    dataInfo.outData = (unsigned char *)SoftBusCalloc(outLen);
    if (dataInfo.outData == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail when process session out data.");
        return SOFTBUS_MALLOC_ERR;
    }
    dataInfo.inData = (unsigned char *)data;
    dataInfo.inLen = dataHead->dataLen;
    dataInfo.outLen = outLen;

    int32_t ret = ClientTransProxyDecryptPacketData(channelId, dataHead->seq, &dataInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "decrypt err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_DECRYPT_ERR;
    }

    if (ClientTransProxySessionDataLenCheck(dataInfo.outLen, (SessionPktType)(dataHead->flags)) != SOFTBUS_OK) {
        TRANS_LOGE(
            TRANS_SDK, "data len is too large outlen=%{public}d, flags=%{public}d", dataInfo.outLen, dataHead->flags);
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }

    TRANS_LOGD(TRANS_SDK, "ProcessData debug: outlen=%{public}d", dataInfo.outLen);
    if (ClientTransProxyBytesNotifySession(channelId, dataHead, (const char *)dataInfo.outData,
                                           dataInfo.outLen) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    SoftBusFree(dataInfo.outData);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyNoSubPacketTlvProc(int32_t channelId, const char *data, uint32_t len)
{
    DataHeadTlvPacketHead pktHead;
    uint32_t newPktHeadSize = 0;
    int32_t ret = TransProxyParseTlv(data, &pktHead, &newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "proxy channel parse tlv failed, ret=%{public}d", ret);
        return ret;
    }
    ClientUnPackTlvPackHead(&pktHead);
    TRANS_LOGI(TRANS_SDK, "proxy channel parse tlv newPktHeadSize=%{public}d", newPktHeadSize);

    if (pktHead.magicNumber != MAGIC_NUMBER) {
        TRANS_LOGE(TRANS_SDK, "invalid magicNumber=%{public}x, channelId=%{public}d, len=%{public}u",
            pktHead.magicNumber, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if (pktHead.dataLen == 0) {
        TRANS_LOGE(TRANS_SDK, "invalid dataLen=%{public}u, channelId=%{public}d, len=%{public}u",
            pktHead.dataLen, channelId, len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    TRANS_LOGD(TRANS_SDK, "NoSubPacketProc dataLen=%{public}u, inputLen=%{public}u", pktHead.dataLen, len);
    if (len <= newPktHeadSize || (pktHead.dataLen != (len - newPktHeadSize))) {
        TRANS_LOGE(TRANS_SDK, "dataLen error, channelId=%{public}d, len=%{public}u, dataLen=%{public}u",
            channelId, len, pktHead.dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    ret = ClientTransProxyProcData(channelId, &pktHead, data + newPktHeadSize);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err, channelId=%{public}d, len=%{public}u", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyNoSubPacketProc(int32_t channelId, const char *data, uint32_t len)
{
    bool supportTlv = false;
    int32_t res = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    if (res != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get support tlv failed, channelId=%{public}d", channelId);
        return res;
    }
    if (supportTlv) {
        return ClientTransProxyNoSubPacketTlvProc(channelId, data, len);
    }
    PacketHead head;
    if (len < sizeof(PacketHead)) {
        TRANS_LOGE(TRANS_SDK, "check len failed, len=%{public}d", len);
        return SOFTBUS_INVALID_PARAM;
    }
    if (memcpy_s(&head, sizeof(PacketHead), data, sizeof(PacketHead)) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy packetHead failed");
        return SOFTBUS_MEM_ERR;
    }
    ClientUnPackPacketHead(&head);
    if ((uint32_t)head.magicNumber != MAGIC_NUMBER) {
        TRANS_LOGE(TRANS_SDK, "invalid magicNumber=%{public}x, channelId=%{public}d, len=%{public}d",
            head.magicNumber, channelId, len);
        return SOFTBUS_INVALID_DATA_HEAD;
    }
    if (head.dataLen <= 0) {
        TRANS_LOGE(TRANS_SDK, "invalid dataLen=%{public}d, channelId=%{public}d, len=%{public}d",
            head.dataLen, channelId, len);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    TRANS_LOGD(TRANS_SDK, "NoSubPacketProc dataLen=%{public}d, inputLen=%{public}d", head.dataLen, len);
    if (len <= sizeof(PacketHead) || (head.dataLen != (int32_t)(len - sizeof(PacketHead)))) {
        TRANS_LOGE(TRANS_SDK, "dataLen error, channelId=%{public}d, len=%{public}d, dataLen=%{public}d",
            channelId, len, head.dataLen);
        return SOFTBUS_TRANS_INVALID_DATA_LENGTH;
    }
    int32_t ret = ClientTransProxyProcessSessionData(channelId, &head, data + sizeof(PacketHead));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process data err, channelId=%{public}d, len=%{public}d", channelId, len);
        return ret;
    }
    return SOFTBUS_OK;
}

static ChannelSliceProcessor *ClientTransProxyGetChannelSliceProcessor(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return processor;
        }
    }

    ChannelSliceProcessor *node = (ChannelSliceProcessor *)SoftBusCalloc(sizeof(ChannelSliceProcessor));
    if (node == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc err");
        return NULL;
    }
    node->channelId = channelId;
    ListInit(&(node->head));
    ListAdd(&(g_channelSliceProcessorList->list), &(node->head));
    g_channelSliceProcessorList->cnt++;
    TRANS_LOGI(TRANS_SDK, "add new node, channelId=%{public}d", channelId);
    return node;
}

static void ClientTransProxyClearProcessor(SliceProcessor *processor)
{
    if (processor->data != NULL) {
        SoftBusFree(processor->data);
        processor->data = NULL;
    }
    processor->active = false;
    processor->bufLen = 0;
    processor->dataLen = 0;
    processor->expectedSeq = 0;
    processor->sliceNumber = 0;
    processor->timeout = 0;
}

int32_t TransProxyDelSliceProcessorByChannelId(int32_t channelId)
{
    ChannelSliceProcessor *node = NULL;
    ChannelSliceProcessor *next = NULL;

    if (g_channelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_INIT, "not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock err");
        return SOFTBUS_LOCK_ERR;
    }
    LIST_FOR_EACH_ENTRY_SAFE(node, next, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (node->channelId == channelId) {
            for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
                ClientTransProxyClearProcessor(&(node->processor[i]));
            }
            ListDelete(&(node->head));
            TRANS_LOGI(TRANS_SDK, "delete channelId=%{public}d", channelId);
            SoftBusFree(node);
            g_channelSliceProcessorList->cnt--;
            (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    return SOFTBUS_OK;
}

static int32_t ClientTransProxySliceProcessChkPkgIsValid(
    const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    (void)data;
    if (head->sliceNum != processor->sliceNumber || head->sliceSeq != processor->expectedSeq) {
        TRANS_LOGE(TRANS_SDK, "unmatched normal slice received, head sliceNum=%{public}d, sliceSeq=%{public}d,\
            processor sliceNumber=%{public}d, expectedSeq=%{public}d", head->sliceNum,
            head->sliceSeq, processor->sliceNumber, processor->expectedSeq);
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID;
    }
    if (processor->dataLen > processor->bufLen || (int32_t)len > processor->bufLen - processor->dataLen) {
        TRANS_LOGE(TRANS_SDK, "data len invalid %{public}u, %{public}d", len, processor->dataLen);
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH;
    }
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_SDK, "data NULL");
        return SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL;
    }
    return SOFTBUS_OK;
}

static int32_t ClientGetActualDataLen(const SliceHead *head, uint32_t *actualDataLen)
{
    uint32_t maxDataLen =
        (head->priority == PROXY_CHANNEL_PRORITY_MESSAGE) ? g_proxyMaxMessageBufSize : g_proxyMaxByteBufSize;
    // The encrypted data length is longer than the actual data length
    maxDataLen += SLICE_LEN;

    if ((head->sliceNum < 0) || ((uint32_t)head->sliceNum > (maxDataLen / SLICE_LEN))) {
        TRANS_LOGE(TRANS_SDK, "invalid sliceNum=%{public}d", head->sliceNum);
        return SOFTBUS_INVALID_DATA_HEAD;
    }

    *actualDataLen = head->sliceNum * SLICE_LEN;
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyFirstSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    ClientTransProxyClearProcessor(processor);

    uint32_t actualDataLen = 0;
    int32_t ret = ClientGetActualDataLen(head, &actualDataLen);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    uint32_t maxLen = 0;
    bool supportTlv = false;
    ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get support tlv failed, channelId=%{public}d", channelId);
        return ret;
    }
    if (supportTlv) {
        maxLen = actualDataLen + PROXY_TLV_PKT_HEAD + OVERHEAD_LEN;
    } else {
        maxLen = actualDataLen + sizeof(PacketHead) + OVERHEAD_LEN;
    }
    processor->data = (char *)SoftBusCalloc(maxLen);
    if (processor->data == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc fail when proc first slice package");
        return SOFTBUS_MALLOC_ERR;
    }
    processor->bufLen = (int32_t)maxLen;
    if (memcpy_s(processor->data, maxLen, data, len) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy fail when proc first slice package");
        SoftBusFree(processor->data);
        processor->data = NULL;
        return SOFTBUS_MEM_ERR;
    }
    processor->sliceNumber = head->sliceNum;
    processor->expectedSeq = 1;
    processor->dataLen = (int32_t)len;
    processor->active = true;
    processor->timeout = 0;

    TRANS_LOGI(TRANS_SDK, "FirstSliceProcess ok");
    return SOFTBUS_OK;
}

static bool IsValidCheckoutProcess(int32_t channelId)
{
    ChannelSliceProcessor *processor = NULL;
    LIST_FOR_EACH_ENTRY(processor, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        if (processor->channelId == channelId) {
            return true;
        }
    }

    TRANS_LOGE(TRANS_SDK, "Process not exist.");
    return false;
}

static int32_t ClientTransProxyLastSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len, int32_t channelId)
{
    int32_t ret = ClientTransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen, (uint32_t)(processor->bufLen - processor->dataLen), data, len) !=
        EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy fail when proc last slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += (int32_t)len;

    ret = ClientTransProxyNoSubPacketProc(channelId, processor->data, (uint32_t)processor->dataLen);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "process packets err");
        return ret;
    }

    if (IsValidCheckoutProcess(channelId)) {
        ClientTransProxyClearProcessor(processor);
    }

    TRANS_LOGI(TRANS_SDK, "LastSliceProcess ok");
    return ret;
}

static int32_t ClientTransProxyNormalSliceProcess(
    SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    int32_t ret = ClientTransProxySliceProcessChkPkgIsValid(processor, head, data, len);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if (memcpy_s(processor->data + processor->dataLen,
        (uint32_t)(processor->bufLen - processor->dataLen), data, len) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy fail when proc normal slice");
        return SOFTBUS_MEM_ERR;
    }
    processor->expectedSeq++;
    processor->dataLen += (int32_t)len;
    processor->timeout = 0;
    TRANS_LOGI(TRANS_SDK, "NormalSliceProcess ok");
    return ret;
}

static int ClientTransProxySubPacketProc(int32_t channelId, const SliceHead *head, const char *data, uint32_t len)
{
    if (g_channelSliceProcessorList == NULL) {
        TRANS_LOGE(TRANS_SDK, "TransProxySubPacketProc not init");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "lock err");
        return SOFTBUS_LOCK_ERR;
    }

    ChannelSliceProcessor *channelProcessor = ClientTransProxyGetChannelSliceProcessor(channelId);
    if (channelProcessor == NULL) {
        SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
        return SOFTBUS_TRANS_GET_CLIENT_PROXY_NULL;
    }

    int ret;
    int32_t index = head->priority;
    SliceProcessor *processor = &(channelProcessor->processor[index]);
    if (head->sliceSeq == 0) {
        ret = ClientTransProxyFirstSliceProcess(processor, head, data, len, channelId);
    } else if (head->sliceNum == head->sliceSeq + 1) {
        ret = ClientTransProxyLastSliceProcess(processor, head, data, len, channelId);
    } else {
        ret = ClientTransProxyNormalSliceProcess(processor, head, data, len);
    }

    SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    if (ret != SOFTBUS_OK) {
        ClientTransProxyClearProcessor(processor);
    }
    return ret;
}

static int32_t ClientTransProxySliceProc(int32_t channelId, const char *data, uint32_t len)
{
    if (data == NULL || len <= sizeof(SliceHead)) {
        TRANS_LOGE(TRANS_SDK, "data null or len error. len=%{public}d", len);
        return SOFTBUS_INVALID_PARAM;
    }

    SliceHead headSlice = *(SliceHead *)data;
    ClientUnPackSliceHead(&headSlice);
    if (ClientTransProxyCheckSliceHead(&headSlice) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "invalid slihead");
        return SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD;
    }

    uint32_t dataLen = len - sizeof(SliceHead);
    if (headSlice.sliceNum == 1) { // no sub packets
        TRANS_LOGD(TRANS_SDK, "no sub packets proc, channelId=%{public}d", channelId);
        return ClientTransProxyNoSubPacketProc(channelId, data + sizeof(SliceHead), dataLen);
    } else {
        TRANS_LOGI(TRANS_SDK, "sub packets proc sliceNum=%{public}d", headSlice.sliceNum);
        return ClientTransProxySubPacketProc(channelId, &headSlice, data + sizeof(SliceHead), dataLen);
    }
}

static void ClientTransProxySliceTimerProc(void)
{
#define SLICE_PACKET_TIMEOUT 10 // 10s
    ChannelSliceProcessor *removeNode = NULL;
    ChannelSliceProcessor *nextNode = NULL;

    if (g_channelSliceProcessorList == NULL || g_channelSliceProcessorList->cnt == 0) {
        return;
    }
    if (SoftBusMutexLock(&g_channelSliceProcessorList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "TransProxySliceTimerProc lock mutex fail!");
        return;
    }

    LIST_FOR_EACH_ENTRY_SAFE(removeNode, nextNode, &g_channelSliceProcessorList->list, ChannelSliceProcessor, head) {
        for (int i = PROXY_CHANNEL_PRORITY_MESSAGE; i < PROXY_CHANNEL_PRORITY_BUTT; i++) {
            if (removeNode->processor[i].active == true) {
                removeNode->processor[i].timeout++;
                if (removeNode->processor[i].timeout >= SLICE_PACKET_TIMEOUT) {
                    TRANS_LOGE(TRANS_SDK, "timeout=%{public}d", removeNode->processor[i].timeout);
                    ClientTransProxyClearProcessor(&removeNode->processor[i]);
                }
            }
        }
    }
    (void)SoftBusMutexUnlock(&g_channelSliceProcessorList->lock);
    return;
}

int32_t ClientTransProxyOnDataReceived(int32_t channelId, const void *data, uint32_t len, SessionPktType type)
{
    (void)type;
    if (data == NULL) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyOnDataReceived data null. channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }

    ProxyChannelInfoDetail info;
    if (ClientTransProxyGetInfoByChannelId(channelId, &info) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID;
    }
    if (!info.isEncrypted) {
        return g_sessionCb.OnDataReceived(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
    }

    return ClientTransProxySliceProc(channelId, (char *)data, len);
}

void ClientTransProxyCloseChannel(int32_t channelId)
{
    (void)ClientTransProxyDelChannelInfo(channelId);
    (void)TransProxyDelSliceProcessorByChannelId(channelId);
    TRANS_LOGI(TRANS_SDK, "TransCloseProxyChannel, channelId=%{public}d", channelId);
    if (ServerIpcCloseChannel(NULL, channelId, CHANNEL_TYPE_PROXY) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "server close err. channelId=%{public}d", channelId);
    }
}

static uint8_t *TransProxyPackTlvData(DataHead *pktHead, int32_t tlvBufferSize, uint32_t dataLen)
{
    int32_t newDataHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    uint8_t *buf = (uint8_t *)SoftBusCalloc(dataLen + newDataHeadSize);
    if (buf == NULL) {
        TRANS_LOGE(TRANS_SDK, "malloc buf failed");
        return NULL;
    }
    if (memcpy_s(buf, dataLen + newDataHeadSize, &pktHead->magicNum, MAGICNUM_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_SDK, "memcpy magicNum failed");
        return NULL;
    }

    if (memcpy_s(buf + MAGICNUM_SIZE, dataLen + newDataHeadSize, &pktHead->tlvCount,
        TLVCOUNT_SIZE) != EOK) {
        SoftBusFree(buf);
        TRANS_LOGE(TRANS_SDK, "memcpy tlvCount failed");
        return NULL;
    }

    uint8_t *temp = buf + MAGICNUM_SIZE + TLVCOUNT_SIZE;
    for (int index = 0; index < pktHead->tlvCount; index++) {
        TlvElement *ement = (TlvElement *)pktHead->tlvElement;
        if (memcpy_s(temp, dataLen + newDataHeadSize, &ement->type, sizeof(ement->type)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment type failed");
            return NULL;
        }

        temp += sizeof(ement->type);
        if (memcpy_s(temp, dataLen + newDataHeadSize, &ement->length, sizeof(ement->length)) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment length failed");
            return NULL;
        }

        temp += sizeof(ement->length);
        if (memcpy_s(temp, dataLen + newDataHeadSize, ement->value, ement->length) != EOK) {
            SoftBusFree(buf);
            TRANS_LOGE(TRANS_SDK, "memcpy tlvEment value failed");
            return NULL;
        }

        temp += ement->length;
        pktHead->tlvElement += sizeof(TlvElement);
    }
    return buf;
}

static int32_t ClientTransProxyPackTlvBytes(int32_t channelId, ClientProxyDataInfo *dataInfo,
    ProxyChannelInfoDetail *info, uint32_t dataSeq, SessionPktType flag)
{
    if (dataInfo == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t seq = info->sequence;
    char *sessionKey = info->sessionKey;
    uint32_t dataLen = dataInfo->inLen + OVERHEAD_LEN;
    bool needAck = false;
    int32_t ret = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, NULL, &needAck);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get need ack fail");
    DataHead pktHead;
    int32_t tlvBufferSize = 0;
    ret = ProxyBuildTlvDataHead(&pktHead, seq, flag, dataLen, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv dataHead fail");
    ret = ProxyBuildNeedAckTlvData(&pktHead, needAck, dataSeq, &tlvBufferSize);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "build tlv needAck fail");
    dataInfo->outData = TransProxyPackTlvData(&pktHead, tlvBufferSize, dataLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_SDK, "TransProxyPackTlvData error");
        ReleaseTlvValueBuffer(&pktHead);
        SoftBusFree(pktHead.tlvElement);
        return SOFTBUS_TRANS_PACK_TLV_DATA_FAILED;
    }
    ReleaseTlvValueBuffer(&pktHead);
    SoftBusFree(pktHead.tlvElement);
    int32_t newDataHeadSize = MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize;
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + (uint32_t)newDataHeadSize;

    uint32_t outLen = 0;
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        SoftBusFree(dataInfo->outData);
        return SOFTBUS_MEM_ERR;
    }
    char *outData = (char *)dataInfo->outData + newDataHeadSize;
    ret = SoftBusEncryptDataWithSeq(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);

    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "encrypt error, ret=%{public}d", ret);
        outData = NULL;
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyEncryptWithSeq channelId=%{public}d", channelId);
        SoftBusFree(dataInfo->outData);
        dataInfo->outData = NULL;
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t ClientTransProxyPackBytes(int32_t channelId, ClientProxyDataInfo *dataInfo, ProxyChannelInfoDetail *info,
    uint32_t dataSeq, SessionPktType flag)
{
#define MAGIC_NUMBER 0xBABEFACE
    if (dataInfo == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    bool supportTlv = false;
    int32_t res = GetSupportTlvAndNeedAckById(channelId, CHANNEL_TYPE_PROXY, &supportTlv, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(res == SOFTBUS_OK, res, TRANS_SDK, "get support tlv fail");
    if (supportTlv) {
        return ClientTransProxyPackTlvBytes(channelId, dataInfo, info, dataSeq, flag);
    }
    int32_t seq = info->sequence;
    char *sessionKey = info->sessionKey;
    dataInfo->outLen = dataInfo->inLen + OVERHEAD_LEN + sizeof(PacketHead);
    dataInfo->outData = (uint8_t *)SoftBusCalloc(dataInfo->outLen);
    if (dataInfo->outData == NULL) {
        TRANS_LOGE(TRANS_SDK, "calloc error");
        return SOFTBUS_MEM_ERR;
    }

    uint32_t outLen = 0;
    AesGcmCipherKey cipherKey = { 0 };
    cipherKey.keyLen = SESSION_KEY_LENGTH;
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        TRANS_LOGE(TRANS_SDK, "memcpy key error.");
        SoftBusFree(dataInfo->outData);
        return SOFTBUS_MEM_ERR;
    }
    char *outData = (char *)dataInfo->outData + sizeof(PacketHead);
    int32_t ret = SoftBusEncryptDataWithSeq(&cipherKey, (const unsigned char *)dataInfo->inData,
        dataInfo->inLen, (unsigned char *)outData, &outLen, seq);
    (void)memset_s(cipherKey.key, SESSION_KEY_LENGTH, 0, SESSION_KEY_LENGTH);

    if (ret != SOFTBUS_OK || outLen != dataInfo->inLen + OVERHEAD_LEN) {
        TRANS_LOGE(TRANS_SDK, "encrypt error, ret=%{public}d", ret);
        outData = NULL;
        SoftBusFree(dataInfo->outData);
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyEncryptWithSeq channelId=%{public}d", channelId);
        return SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR;
    }
    PacketHead *pktHead = (PacketHead *)dataInfo->outData;
    pktHead->magicNumber = MAGIC_NUMBER;
    pktHead->seq = seq;
    pktHead->flags = flag;
    pktHead->dataLen = (int32_t)((int32_t)dataInfo->outLen - sizeof(PacketHead));
    ClientPackPacketHead(pktHead);

    return SOFTBUS_OK;
}

static int32_t SessionPktTypeToProxyIndex(SessionPktType packetType)
{
    switch (packetType) {
        case TRANS_SESSION_MESSAGE:
        case TRANS_SESSION_ASYNC_MESSAGE:
        case TRANS_SESSION_ACK:
            return PROXY_CHANNEL_PRORITY_MESSAGE;
        case TRANS_SESSION_BYTES:
            return PROXY_CHANNEL_PRORITY_BYTES;
        default:
            return PROXY_CHANNEL_PRORITY_FILE;
    }
}

int32_t TransProxyPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, ProxyChannelInfoDetail *info, SessionPktType pktType)
{
    if (data == NULL || info == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ClientProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    uint32_t dataSeq = 0;
    int32_t ret = ClientTransProxyPackBytes(channelId, &dataInfo, info, dataSeq, pktType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyPackBytes error, channelId=%{public}d", channelId);
        return ret;
    }

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SLICE_LEN - 1)) / (uint32_t)SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        TRANS_LOGE(TRANS_FILE, "Data overflow");
        SoftBusFree(dataInfo.outData);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t i = 0; i < sliceNum; i++) {
        uint32_t dataLen = (i == (sliceNum - 1U)) ? (dataInfo.outLen - i * SLICE_LEN) : SLICE_LEN;
        int32_t offset = (int32_t)(i * SLICE_LEN);

        uint8_t *sliceData = (uint8_t *)SoftBusCalloc(dataLen + sizeof(SliceHead));
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "malloc slice data error, channelId=%{public}d", channelId);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MALLOC_ERR;
        }
        SliceHead *slicehead = (SliceHead *)sliceData;
        slicehead->priority = SessionPktTypeToProxyIndex(pktType);
        slicehead->sliceNum = (int32_t)sliceNum;
        slicehead->sliceSeq = (int32_t)i;
        ClientPackSliceHead(slicehead);
        if (memcpy_s(sliceData + sizeof(SliceHead), dataLen, dataInfo.outData + offset, dataLen) != EOK) {
            TRANS_LOGE(TRANS_SDK, "memcpy_s error, channelId=%{public}d", channelId);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return SOFTBUS_MEM_ERR;
        }

        int ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            SoftBusFree(dataInfo.outData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    SoftBusFree(dataInfo.outData);

    TRANS_LOGI(TRANS_SDK, "TransProxyPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendBytes(int32_t channelId, const void *data, uint32_t len, bool needAck)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send bytes: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    if (needAck) {
        ret = AddPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
            return ret;
        }
        ret = TransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_BYTES);
        if (ret != SOFTBUS_OK) {
            DelPendingPacketbyChannelId(channelId, info.sequence, PENDING_TYPE_PROXY);
            return ret;
        }
        TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, seq=%{public}d", channelId, info.sequence);
        return ProcPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
    }
    return TransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_BYTES);
}

int32_t TransProxyAsyncPackAndSendData(
    int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq, SessionPktType pktType)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail");

    ClientProxyDataInfo dataInfo = { (uint8_t *)data, len, (uint8_t *)data, len };
    ret = ClientTransProxyPackTlvBytes(channelId, &dataInfo, &info, dataSeq, pktType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "ClientTransProxyPackTlvBytes error, channelId=%{public}d", channelId);
        return ret;
    }

    uint32_t sliceNum = (dataInfo.outLen + (uint32_t)(SLICE_LEN - 1)) / (uint32_t)SLICE_LEN;
    if (sliceNum > INT32_MAX) {
        TRANS_LOGE(TRANS_FILE, "Data overflow, sliceNum=%{public}u, channelId=%{public}d", sliceNum, channelId);
        return SOFTBUS_INVALID_NUM;
    }
    for (uint32_t i = 0; i < sliceNum; i++) {
        uint32_t dataLen = (i == (sliceNum - 1U)) ? (dataInfo.outLen - i * SLICE_LEN) : SLICE_LEN;
        int32_t offset = (int32_t)(i * SLICE_LEN);

        uint8_t *sliceData = (uint8_t *)SoftBusCalloc(dataLen + sizeof(SliceHead));
        if (sliceData == NULL) {
            TRANS_LOGE(TRANS_SDK, "malloc slice data error, channelId=%{public}d", channelId);
            return SOFTBUS_MALLOC_ERR;
        }
        SliceHead *slicehead = (SliceHead *)sliceData;
        slicehead->priority = SessionPktTypeToProxyIndex(pktType);
        slicehead->sliceNum = (int32_t)sliceNum;
        slicehead->sliceSeq = (int32_t)i;
        ClientPackSliceHead(slicehead);
        if (memcpy_s(sliceData + sizeof(SliceHead), dataLen, dataInfo.outData + offset, dataLen) != EOK) {
            TRANS_LOGE(TRANS_SDK, "memcpy_s error, channelId=%{public}d", channelId);
            SoftBusFree(sliceData);
            return SOFTBUS_MEM_ERR;
        }

        int ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, sliceData, dataLen + sizeof(SliceHead), pktType);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_SDK, "ServerIpcSendMessage error, channelId=%{public}d, ret=%{public}d", channelId, ret);
            SoftBusFree(sliceData);
            return ret;
        }

        SoftBusFree(sliceData);
    }
    TRANS_LOGI(TRANS_SDK, "TransProxyAsyncPackAndSendData success, channelId=%{public}d", channelId);
    return SOFTBUS_OK;
}

int32_t TransProxyChannelAsyncSendBytes(int32_t channelId, const void *data, uint32_t len, uint32_t dataSeq)
{
    if (data == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send bytes: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    ret = TransProxyAsyncPackAndSendData(channelId, data, len, dataSeq, TRANS_SESSION_BYTES);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "proxy async send data fail!");
    int32_t socketId = 0;
    ret = ClientGetSessionIdByChannelId(channelId, CHANNEL_TYPE_PROXY, &socketId, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "get sessionId fail, ret=%{public}d", ret);
        return ret;
    }
    ret = DataSeqInfoListAddItem(dataSeq, channelId, socketId, CHANNEL_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add dataSeqInfoList fail, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransProxyChannelSendMessage(int32_t channelId, const void *data, uint32_t len)
{
    ProxyChannelInfoDetail info;
    int32_t ret = ClientTransProxyGetInfoByChannelId(channelId, &info);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_SDK, "get info fail!");

    if (!info.isEncrypted) {
        // auth channel only can send bytes
        ret = ServerIpcSendMessage(channelId, CHANNEL_TYPE_PROXY, data, len, TRANS_SESSION_BYTES);
        TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }

    ret = AddPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "add pending packet failed, channelId=%{public}d.", channelId);
        return ret;
    }
    ret = TransProxyPackAndSendData(channelId, data, len, &info, TRANS_SESSION_MESSAGE);
    if (ret != SOFTBUS_OK) {
        DelPendingPacketbyChannelId(channelId, info.sequence, PENDING_TYPE_PROXY);
        return ret;
    }
    TRANS_LOGI(TRANS_SDK, "send msg: channelId=%{public}d, seq=%{public}d", channelId, info.sequence);
    return ProcPendingPacket(channelId, info.sequence, PENDING_TYPE_PROXY);
}

int32_t ClientTransProxyOnChannelBind(int32_t channelId, int32_t channelType)
{
    if (g_sessionCb.OnChannelBind == NULL) {
        TRANS_LOGE(TRANS_SDK, "OnChannelBind is null, channelId=%{public}d.", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t ret = g_sessionCb.OnChannelBind(channelId, channelType);
    if (ret == SOFTBUS_NOT_NEED_UPDATE) {
        return SOFTBUS_OK;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_SDK, "notify OnChannelBind openfail channelId=%{public}d.", channelId);
        return ret;
    }

    return SOFTBUS_OK;
}
