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

#include "transproxyprocessdata_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_proxy_process_data.c"

namespace OHOS {
class TransProxyProcessData {
public:
    TransProxyProcessData()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransProxyProcessData()
    {
        isInited_ = false;
        TransProxyManagerDeinit();
    }

    bool IsInited(void)
    {
        return isInited_;
    }

private:
    volatile bool isInited_;
};

static void FillDataHeadTlvPacketHead(FuzzedDataProvider &provider, DataHeadTlvPacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<uint32_t>();
    data->tlvCount = provider.ConsumeIntegral<uint8_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->dataSeq = provider.ConsumeIntegral<uint32_t>();
    data->flags = provider.ConsumeIntegral<uint32_t>();
    data->dataLen = provider.ConsumeIntegral<uint32_t>();
    data->needAck = provider.ConsumeBool();
}

void TransUnPackTlvPackHeadTest(FuzzedDataProvider &provider)
{
    TransUnPackTlvPackHead(nullptr);

    DataHeadTlvPacketHead data;
    (void)memset_s(&data, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &data);

    TransUnPackTlvPackHead(&data);
}

static void FillSliceHead(FuzzedDataProvider &provider, SliceHead *data)
{
    data->priority = provider.ConsumeIntegral<int32_t>();
    data->sliceNum = provider.ConsumeIntegral<int32_t>();
    data->sliceSeq = provider.ConsumeIntegral<int32_t>();
    data->reserved = provider.ConsumeIntegral<int32_t>();
}

void TransUnPackSliceHeadTest(FuzzedDataProvider &provider)
{
    TransUnPackSliceHead(nullptr);

    SliceHead data;
    (void)memset_s(&data, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &data);

    TransPackSliceHead(&data);
    TransUnPackSliceHead(&data);
}

static void FillPacketHead(FuzzedDataProvider &provider, PacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<int32_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->flags = provider.ConsumeIntegral<int32_t>();
    data->dataLen = provider.ConsumeIntegral<int32_t>();
}

void TransProxyPackBytesTest(FuzzedDataProvider &provider)
{
    PacketHead data;
    (void)memset_s(&data, sizeof(PacketHead), 0, sizeof(PacketHead));
    FillPacketHead(provider, &data);
    TransPackPacketHead(&data);
    TransUnPackPacketHead(&data);

    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    SessionPktType flag = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    std::string providerSessionKey = provider.ConsumeBytesAsString(SESSION_KEY_LENGTH - 1);
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SESSION_KEY_LENGTH, providerSessionKey.c_str()) != EOK) {
        return;
    }

    TransProxyPackBytes(channelId, nullptr, nullptr, flag, 0);

    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));

    TransProxyPackBytes(channelId, &dataInfo, sessionKey, flag, 0);

    dataInfo.inLen = MAX_MALLOC_SIZE;
    TransProxyPackBytes(channelId, &dataInfo, sessionKey, flag, 0);
}

void TransProxyPackTlvBytesTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));
    pktHead.magicNum = provider.ConsumeIntegral<uint32_t>();
    pktHead.tlvCount = provider.ConsumeIntegral<uint8_t>();

    int32_t tlvBufferSize = provider.ConsumeIntegral<int8_t>();
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    TransProxyPackTlvData(nullptr, tlvBufferSize, dataLen);
    dataLen = -(MAGICNUM_SIZE + TLVCOUNT_SIZE + tlvBufferSize);
    TransProxyPackTlvData(&pktHead, tlvBufferSize, dataLen);

    int32_t finalSeq = provider.ConsumeIntegral<int32_t>();
    int32_t flag = provider.ConsumeIntegral<int32_t>();
    (void)ProxyBuildTlvDataHead(nullptr, finalSeq, flag, dataLen, &tlvBufferSize);

    bool needAck = provider.ConsumeBool();
    uint32_t dataSeqs = provider.ConsumeIntegral<uint32_t>();
    (void)ProxyBuildNeedAckTlvData(nullptr, needAck, dataSeqs, &tlvBufferSize);

    SessionPktType flag2 = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    std::string providerSessionKey = provider.ConsumeBytesAsString(SESSION_KEY_LENGTH - 1);
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SESSION_KEY_LENGTH, providerSessionKey.c_str()) != EOK) {
        return;
    }
    int32_t seq = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyPackTlvBytes(nullptr, sessionKey, flag2, seq, nullptr);

    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));

    DataHeadTlvPacketHead info;
    (void)memset_s(&info, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &info);
    TransProxyPackTlvBytes(&dataInfo, nullptr, flag2, seq, &info);
}

void TransProxyPackDataTest(FuzzedDataProvider &provider)
{
    SessionPktType packetType = TRANS_SESSION_ACK;
    (void)SessionPktTypeToProxyIndex(packetType);
    packetType = TRANS_SESSION_BYTES;
    (void)SessionPktTypeToProxyIndex(packetType);
    packetType = TRANS_SESSION_BYTES;
    (void)SessionPktTypeToProxyIndex(packetType);
    packetType = static_cast<SessionPktType>(provider.ConsumeIntegralInRange<uint16_t>(
        TRANS_SESSION_FILE_FIRST_FRAME, TRANS_SESSION_FILE_ACK_RESPONSE_SENT));
    (void)SessionPktTypeToProxyIndex(packetType);

    uint32_t sliceNum = provider.ConsumeIntegral<uint32_t>();
    uint32_t cnt = provider.ConsumeIntegral<uint32_t>();
    uint32_t dataLen = 0;
    (void)TransProxyPackData(nullptr, sliceNum, packetType, cnt, &dataLen);
}

void TransProxyCheckSliceHeadTest(FuzzedDataProvider &provider)
{
    (void)TransProxyCheckSliceHead(nullptr);

    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);
    (void)TransProxyCheckSliceHead(&head);

    head.priority = -1;
    (void)TransProxyCheckSliceHead(&head);

    head.priority =
        provider.ConsumeIntegralInRange<uint16_t>(PROXY_CHANNEL_PRORITY_MESSAGE, PROXY_CHANNEL_PRORITY_FILE);
    head.sliceSeq += head.sliceNum;
    (void)TransProxyCheckSliceHead(&head);

    head.sliceNum += head.sliceSeq;
    (void)TransProxyCheckSliceHead(&head);
}

void TransProxyNoSubPacketProcTest(FuzzedDataProvider &provider)
{
    uint32_t len = sizeof(PacketHead) - 1;
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyNoSubPacketProc(nullptr, len, nullptr, channelId);

    PacketHead head;
    (void)memset_s(&head, sizeof(PacketHead), 0, sizeof(PacketHead));
    FillPacketHead(provider, &head);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    (void)TransProxyNoSubPacketProc(&head, len, data, channelId);
    len = provider.ConsumeIntegral<uint32_t>();
    (void)TransProxyNoSubPacketProc(&head, len, data, channelId);

    head.magicNumber = MAGIC_NUMBER;
    (void)TransProxyNoSubPacketProc(&head, len, data, channelId);
    head.dataLen = -1;
    (void)TransProxyNoSubPacketProc(&head, len, data, channelId);
    len = sizeof(PacketHead);
    (void)TransProxyNoSubPacketProc(&head, len, data, channelId);
}

void TransProxyProcessSessionDataTest(FuzzedDataProvider &provider)
{
    (void)TransProxyProcessSessionData(nullptr, nullptr, nullptr);
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));

    PacketHead dataHead;
    (void)memset_s(&dataHead, sizeof(PacketHead), 0, sizeof(PacketHead));
    FillPacketHead(provider, &dataHead);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    (void)TransProxyProcessSessionData(&dataInfo, &dataHead, data);

    dataHead.dataLen = OVERHEAD_LEN;
    (void)TransProxyProcessSessionData(&dataInfo, &dataHead, data);
    dataHead.dataLen = OVERHEAD_LEN + 1;
    (void)TransProxyProcessSessionData(&dataInfo, &dataHead, data);
    dataHead.dataLen = INT32_MAX - 1;
    (void)TransProxyProcessSessionData(&dataInfo, &dataHead, data);
}

static void FillSliceProcessor(FuzzedDataProvider &provider, SliceProcessor *processor)
{
    processor->active = provider.ConsumeIntegral<uint32_t>();
    processor->timeout = provider.ConsumeIntegral<uint32_t>();
    processor->sliceNumber = provider.ConsumeIntegral<uint32_t>();
    processor->expectedSeq = provider.ConsumeIntegral<uint32_t>();
    processor->dataLen = provider.ConsumeIntegral<uint32_t>();
    processor->bufLen = provider.ConsumeIntegral<uint32_t>();
    processor->data = static_cast<char *>(SoftBusCalloc(sizeof(char)));
}

void TransProxyClearProcessorTest(FuzzedDataProvider &provider)
{
    TransProxyClearProcessor(nullptr);
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    TransProxyClearProcessor(&processor);
}

void TransProxyDecryptPacketDataTest(FuzzedDataProvider &provider)
{
    int32_t seq = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyDecryptPacketData(seq, nullptr, nullptr);

    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));

    std::string providerSessionKey = provider.ConsumeBytesAsString(SESSION_KEY_LENGTH - 1);
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SESSION_KEY_LENGTH, providerSessionKey.c_str()) != EOK) {
        return;
    }
    (void)TransProxyDecryptPacketData(seq, &dataInfo, sessionKey);
}

void TransProxySessionDataLenCheckTest(FuzzedDataProvider &provider)
{
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    SessionPktType type = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    (void)TransProxySessionDataLenCheck(len, type);
    (void)TransProxySessionDataLenCheck(len, type);
    type = TRANS_SESSION_BYTES;
    (void)TransProxySessionDataLenCheck(len, type);
    type = TRANS_SESSION_FILE_LAST_FRAME;
    (void)TransProxySessionDataLenCheck(len, type);
    len = 0;
    type = TRANS_SESSION_ASYNC_MESSAGE;
    (void)TransProxySessionDataLenCheck(len, type);
    len = UINT32_MAX - 1;
    (void)TransProxySessionDataLenCheck(len, type);
    type = TRANS_SESSION_BYTES;
    (void)TransProxySessionDataLenCheck(len, type);
    len = 0;
    (void)TransProxySessionDataLenCheck(len, type);
}

void TransProxyFirstSliceProcessTest(FuzzedDataProvider &provider)
{
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    bool supportTlv = provider.ConsumeBool();

    (void)TransProxyFirstSliceProcess(nullptr, nullptr, nullptr, len, supportTlv);
    (void)TransProxyFirstSliceProcess(&processor, &head, data, len, supportTlv);

    head.sliceNum = -1;
    (void)TransProxyFirstSliceProcess(&processor, &head, data, len, supportTlv);
}

void TransProxySliceProcessChkPkgIsValidTest(FuzzedDataProvider &provider)
{
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)TransProxySliceProcessChkPkgIsValid(nullptr, nullptr, data, len);
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    head.sliceNum = processor.sliceNumber;
    head.sliceSeq = processor.expectedSeq;
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    processor.bufLen = processor.dataLen;
    len = 0;
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    processor.data = nullptr;
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    processor.dataLen += processor.bufLen;
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
    head.sliceNum += processor.sliceNumber;
    (void)TransProxySliceProcessChkPkgIsValid(&processor, &head, data, len);
}

void TransGetActualDataLenTest(FuzzedDataProvider &provider)
{
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);
    uint32_t actualDataLen = 0;
    (void)TransGetActualDataLen(nullptr, nullptr);
    (void)TransGetActualDataLen(&head, &actualDataLen);
    head.sliceNum = 0;
    (void)TransGetActualDataLen(&head, &actualDataLen);
    head.sliceNum = -1;
    (void)TransGetActualDataLen(&head, &actualDataLen);
}

void TransProxyNormalSliceProcessTest(FuzzedDataProvider &provider)
{
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)TransProxyNormalSliceProcess(nullptr, nullptr, nullptr, len);
    (void)TransProxyNormalSliceProcess(&processor, &head, data, len);
    head.sliceNum = processor.sliceNumber;
    head.sliceSeq = processor.expectedSeq;
    processor.bufLen = processor.dataLen;
    len = 0;
    (void)TransProxyNormalSliceProcess(&processor, &head, data, len);
}

void TransProxyParseTlvTest(FuzzedDataProvider &provider)
{
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    uint32_t headSize = provider.ConsumeIntegral<uint32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    DataHeadTlvPacketHead head;
    (void)memset_s(&head, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &head);
    (void)CheckLenAndCopyData(len, headSize, data, &head);
    len = headSize;
    (void)CheckLenAndCopyData(len, headSize, data, &head);
    len += headSize;
    (void)CheckLenAndCopyData(len, headSize, data, &head);

    (void)TransProxyParseTlv(len, data, nullptr, nullptr);
    (void)TransProxyParseTlv(len, nullptr, &head, &headSize);
}

void TransProxyNoSubPacketTlvProcTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t newPktHeadSize = provider.ConsumeIntegral<uint32_t>();
    DataHeadTlvPacketHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &pktHead);

    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, nullptr, newPktHeadSize);
    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    pktHead.magicNumber = MAGIC_NUMBER;
    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    pktHead.dataLen = 0;
    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    len = newPktHeadSize;
    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
    pktHead.dataLen = len;
    len += newPktHeadSize;
    (void)TransProxyNoSubPacketTlvProc(channelId, data, len, &pktHead, newPktHeadSize);
}

void TransProxyProcDataTest(FuzzedDataProvider &provider)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));

    DataHeadTlvPacketHead dataHead;
    (void)memset_s(&dataHead, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &dataHead);
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }

    (void)TransProxyProcData(&dataInfo, &dataHead, data);
    dataHead.dataLen = OVERHEAD_LEN;
    (void)TransProxyProcData(&dataInfo, &dataHead, data);
    dataHead.dataLen += 1;
    (void)TransProxyProcData(&dataInfo, &dataHead, data);
}

static uint8_t *TestDataSwitch(const uint8_t *data, size_t size)
{
    if (data == nullptr || size < sizeof(int32_t)) {
        return nullptr;
    }
    uint8_t *dataTemp = static_cast<uint8_t *>(SoftBusCalloc(size + 1));
    if (dataTemp == nullptr) {
        return nullptr;
    }
    if (memcpy_s(dataTemp, size, data, size) != EOK) {
        SoftBusFree(dataTemp);
        return nullptr;
    }
    return dataTemp;
}

void TransProxyPackD2DDataTest(FuzzedDataProvider &provider)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    dataInfo.outLen = provider.ConsumeIntegral<uint32_t>();
    uint32_t sliceNum = provider.ConsumeIntegral<uint32_t>();
    uint32_t cnt = provider.ConsumeIntegral<uint32_t>();
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    SessionPktType pktType = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    (void)TransProxyPackD2DData(&dataInfo, sliceNum, pktType, cnt, &dataLen);
    (void)TransProxyPackD2DData(nullptr, sliceNum, pktType, cnt, &dataLen);
    (void)TransProxyPackD2DData(&dataInfo, sliceNum, pktType, cnt, nullptr);
}

void TransProxyProcessD2DDataTest(FuzzedDataProvider &provider)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    int32_t businessType = provider.ConsumeIntegral<int32_t>();
    PacketD2DHead dataHead;
    (void)memset_s(&dataHead, sizeof(PacketD2DHead), 0, sizeof(PacketD2DHead));
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, data, businessType);
    (void)TransProxyProcessD2DData(&dataInfo, nullptr, data, businessType);
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, nullptr, businessType);
    (void)TransProxyProcessD2DData(nullptr, &dataHead, data, businessType);
    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, data, businessType);
    dataHead.dataLen = SHORT_TAG_LEN;
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, data, businessType);
    dataHead.dataLen = SHORT_TAG_LEN + 1;
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, data, businessType);
    dataHead.dataLen = INT32_MAX - 1;
    (void)TransProxyProcessD2DData(&dataInfo, &dataHead, data, businessType);
}

void TransProxyDecryptD2DDataTest(const uint8_t *data, size_t size)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    FuzzedDataProvider provider(data, size);
    std::string providerSessionKey1 = provider.ConsumeBytesAsString(SHORT_SESSION_KEY_LENGTH - 1);
    char sessionKey[SHORT_SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SHORT_SESSION_KEY_LENGTH, providerSessionKey1.c_str()) != EOK) {
        return;
    }
    std::string providerSessionKey2 = provider.ConsumeBytesAsString(GCM_IV_LEN - 1);
    unsigned char sessionCommonIv[GCM_IV_LEN] = { 0 };
    if (memcpy_s(sessionCommonIv, GCM_IV_LEN, providerSessionKey2.c_str(), GCM_IV_LEN - 1) != EOK) {
        return;
    }
    int32_t businessType;
    GenerateInt32(businessType);
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, sessionKey, sessionCommonIv);
    GenerateUint32(dataInfo.inLen);
    GenerateUint32(dataInfo.outLen);
    dataInfo.inData = TestDataSwitch(data, size);
    dataInfo.outData = TestDataSwitch(data, size);
    if (dataInfo.inData == nullptr || dataInfo.outData == nullptr) {
        return;
    }
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, sessionKey, sessionCommonIv);
    (void)TransProxyDecryptD2DData(businessType, nullptr, sessionKey, sessionCommonIv);
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, nullptr, sessionCommonIv);
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, sessionKey, sessionCommonIv);
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, sessionKey, nullptr);
    businessType = BUSINESS_TYPE_D2D_MESSAGE;
    (void)TransProxyDecryptD2DData(businessType, &dataInfo, sessionKey, sessionCommonIv);
    SoftBusFree(dataInfo.inData);
    SoftBusFree(dataInfo.outData);
}

void TransProxyD2DFirstSliceProcessTest(FuzzedDataProvider &provider)
{
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    SliceHead head;
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    int32_t businessType = provider.ConsumeIntegral<int32_t>();
    (void)TransProxyD2DFirstSliceProcess(&processor, &head, data, len, businessType);
    head.priority =
        provider.ConsumeIntegralInRange<uint16_t>(PROXY_CHANNEL_PRORITY_MESSAGE, PROXY_CHANNEL_PRORITY_FILE);
    head.sliceNum = provider.ConsumeIntegral<uint32_t>();
    (void)TransProxyD2DFirstSliceProcess(&processor, &head, data, len, businessType);
    (void)TransProxyD2DFirstSliceProcess(nullptr, &head, data, len, businessType);
    (void)TransProxyD2DFirstSliceProcess(&processor, nullptr, data, len, businessType);
    (void)TransProxyD2DFirstSliceProcess(&processor, &head, nullptr, len, businessType);
}

void TransProxyPackD2DBytesTest(const uint8_t *data, size_t size)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    FuzzedDataProvider provider(data, size);
    std::string providerSessionKey1 = provider.ConsumeBytesAsString(SHORT_SESSION_KEY_LENGTH - 1);
    char sessionKey[SHORT_SESSION_KEY_LENGTH] = { 0 };
    if (strcpy_s(sessionKey, SHORT_SESSION_KEY_LENGTH, providerSessionKey1.c_str()) != EOK) {
        return;
    }
    std::string providerSessionKey2 = provider.ConsumeBytesAsString(GCM_IV_LEN - 1);
    char sessionIv[GCM_IV_LEN] = { 0 };
    if (strcpy_s(sessionIv, GCM_IV_LEN, providerSessionKey2.c_str()) != EOK) {
        return;
    }
    SessionPktType flag = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    (void)TransProxyPackD2DBytes(&dataInfo, sessionKey, sessionIv, flag);
    GenerateUint32(dataInfo.inLen);
    GenerateUint32(dataInfo.outLen);
    dataInfo.inData = TestDataSwitch(data, size);
    if (dataInfo.inData == nullptr) {
        return;
    }
    (void)TransProxyPackD2DBytes(&dataInfo, sessionKey, sessionIv, flag);
    (void)TransProxyPackD2DBytes(nullptr, sessionKey, sessionIv, flag);
    (void)TransProxyPackD2DBytes(&dataInfo, nullptr, sessionIv, flag);
    (void)TransProxyPackD2DBytes(&dataInfo, sessionKey, nullptr, flag);
    SoftBusFree(dataInfo.inData);
}

void TransPackD2DToBytesExtraDataTest(FuzzedDataProvider &provider)
{
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    SessionPktType flag = static_cast<SessionPktType>(
        provider.ConsumeIntegralInRange<uint16_t>(TRANS_SESSION_BYTES, TRANS_SESSION_ASYNC_MESSAGE));
    uint32_t nonce = provider.ConsumeIntegral<uint32_t>();

    (void)TransGenerateToBytesRandIv(nullptr, nullptr);
    (void)TransPackD2DToBytesExtraData(nullptr, flag, nonce);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransProxyProcessData testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TransUnPackTlvPackHeadTest(provider);
    OHOS::TransUnPackSliceHeadTest(provider);
    OHOS::TransProxyPackBytesTest(provider);
    OHOS::TransProxyPackTlvBytesTest(provider);
    OHOS::TransProxyPackDataTest(provider);
    OHOS::TransProxyCheckSliceHeadTest(provider);
    OHOS::TransProxyNoSubPacketProcTest(provider);
    OHOS::TransProxyProcessSessionDataTest(provider);
    OHOS::TransProxyClearProcessorTest(provider);
    OHOS::TransProxyDecryptPacketDataTest(provider);
    OHOS::TransProxySessionDataLenCheckTest(provider);
    OHOS::TransProxyFirstSliceProcessTest(provider);
    OHOS::TransProxySliceProcessChkPkgIsValidTest(provider);
    OHOS::TransGetActualDataLenTest(provider);
    OHOS::TransProxyNormalSliceProcessTest(provider);
    OHOS::TransProxyParseTlvTest(provider);
    OHOS::TransProxyNoSubPacketTlvProcTest(provider);
    OHOS::TransProxyProcDataTest(provider);
    OHOS::TransProxyPackD2DDataTest(provider);
    OHOS::TransProxyProcessD2DDataTest(provider);
    OHOS::TransProxyDecryptD2DDataTest(data, size);
    OHOS::TransProxyD2DFirstSliceProcessTest(provider);
    OHOS::TransProxyPackD2DBytesTest(data, size);
    OHOS::TransPackD2DToBytesExtraDataTest(provider);
    return 0;
}
