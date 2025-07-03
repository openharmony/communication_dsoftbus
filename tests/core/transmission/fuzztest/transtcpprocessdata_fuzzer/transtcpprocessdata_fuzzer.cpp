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

#include "transtcpprocessdata_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_tcp_process_data.c"

namespace OHOS {
class TransTcpProcessData {
public:
    TransTcpProcessData()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransTcpProcessData()
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

void TransGetDataBufSizeTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)TransGetDataBufSize();
}

void TransGetTdcDataBufMaxSizeTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)TransGetTdcDataBufMaxSize();
}

static void FillTcpDataPacketHead(FuzzedDataProvider &provider, TcpDataPacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<uint32_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->flags = provider.ConsumeIntegral<uint32_t>();
    data->dataLen = provider.ConsumeIntegral<uint32_t>();
}

void UnPackTcpDataPacketHeadTest(FuzzedDataProvider &provider)
{
    TcpDataPacketHead data;
    (void)memset_s(&data, sizeof(TcpDataPacketHead), 0, sizeof(TcpDataPacketHead));
    FillTcpDataPacketHead(provider, &data);

    UnPackTcpDataPacketHead(&data);
}

static void FillTcpDataTlvPacketHead(FuzzedDataProvider &provider, TcpDataTlvPacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<uint32_t>();
    data->tlvCount = provider.ConsumeIntegral<uint8_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->dataSeq = provider.ConsumeIntegral<uint32_t>();
    data->flags = provider.ConsumeIntegral<uint32_t>();
    data->dataLen = provider.ConsumeIntegral<uint32_t>();
    data->needAck = provider.ConsumeBool();
}

void TransTcpDataTlvUnpackTest(FuzzedDataProvider &provider)
{
    TcpDataTlvPacketHead data;
    (void)memset_s(&data, sizeof(TcpDataTlvPacketHead), 0, sizeof(TcpDataTlvPacketHead));
    FillTcpDataTlvPacketHead(provider, &data);

    TransTcpDataTlvUnpack(&data);
}

void TransResizeDataBufferTest(FuzzedDataProvider &provider)
{
    uint32_t pkgLen = 0;
    DataBuf oldBuf;
    (void)memset_s(&oldBuf, sizeof(DataBuf), 0, sizeof(DataBuf));

    (void)TransResizeDataBuffer(&oldBuf, pkgLen);

    pkgLen = provider.ConsumeIntegral<uint8_t>();
    (void)TransResizeDataBuffer(&oldBuf, pkgLen);
}

void MoveNodeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    DataBuf node;
    (void)memset_s(&node, sizeof(DataBuf), 0, sizeof(DataBuf));
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    int32_t pkgHeadSize = provider.ConsumeIntegral<int32_t>();

    (void)MoveNode(channelId, nullptr, dataLen, pkgHeadSize);
    (void)MoveNode(channelId, &node, dataLen, pkgHeadSize);
}

void TransTdcDecryptTest(FuzzedDataProvider &provider)
{
    std::string sessionKey = provider.ConsumeRandomLengthString(UINT8_MAX);
    uint32_t inLen = provider.ConsumeIntegral<uint8_t>();
    std::string in = provider.ConsumeRandomLengthString(inLen);
    char out[UINT8_MAX] = { 0 };
    uint32_t outLen = 0;

    (void)TransTdcDecrypt(nullptr, nullptr, inLen, nullptr, nullptr);
    (void)TransTdcDecrypt(sessionKey.c_str(), in.c_str(), inLen, out, &outLen);
}

void TransTdcRecvFirstDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    size_t len = provider.ConsumeIntegral<uint32_t>();
    int32_t recvLen = 0;
    char *recvBuf = static_cast<char *>(SoftBusCalloc(len));

    (void)TransTdcRecvFirstData(channelId, nullptr, nullptr, fd, len);
    fd = -1;
    (void)TransTdcRecvFirstData(channelId, recvBuf, &recvLen, fd, len);

    len = 0;
    (void)TransTdcRecvFirstData(channelId, recvBuf, &recvLen, fd, len);
    SoftBusFree(recvBuf);
}

void TransTdcUnPackAllDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    DataBuf node;
    (void)memset_s(&node, sizeof(DataBuf), 0, sizeof(DataBuf));
    bool flag = false;

    (void)TransTdcUnPackAllData(channelId, nullptr, nullptr);
    (void)TransTdcUnPackAllData(channelId, &node, &flag);
}

void TransTdcUnPackDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string sessionKey = provider.ConsumeRandomLengthString(UINT8_MAX);
    char plain[UINT8_MAX] = { 0 };
    uint32_t plainLen = 0;

    (void)TransTdcUnPackData(channelId, sessionKey.c_str(), plain, &plainLen, nullptr);
}

void CheckBufLenAndCopyDataTest(FuzzedDataProvider &provider)
{
    uint32_t bufLen = provider.ConsumeIntegral<uint32_t>();
    uint32_t headSize = MAGICNUM_SIZE + TLVCOUNT_SIZE;
    TcpDataTlvPacketHead head;
    (void)memset_s(&head, sizeof(TcpDataTlvPacketHead), 0, sizeof(TcpDataTlvPacketHead));
    FillTcpDataTlvPacketHead(provider, &head);
    char data[MAGICNUM_SIZE + TLVCOUNT_SIZE] = { 0 };

    (void)CheckBufLenAndCopyData(bufLen, headSize, data, &head);

    bufLen = headSize;
    (void)CheckBufLenAndCopyData(bufLen, headSize, data, &head);

    bufLen += headSize;
    (void)CheckBufLenAndCopyData(bufLen, headSize, data, &head);
}

void TransTdcParseTlvTest(FuzzedDataProvider &provider)
{
    uint32_t bufLen = provider.ConsumeIntegral<uint32_t>();
    uint32_t headSize = 0;
    TcpDataTlvPacketHead head;
    (void)memset_s(&head, sizeof(TcpDataTlvPacketHead), 0, sizeof(TcpDataTlvPacketHead));
    FillTcpDataTlvPacketHead(provider, &head);
    char data[MAGICNUM_SIZE + TLVCOUNT_SIZE] = { 0 };

    (void)TransTdcParseTlv(bufLen, nullptr, nullptr, nullptr);

    bufLen += (MAGICNUM_SIZE + TLVCOUNT_SIZE);
    (void)TransTdcParseTlv(bufLen, data, &head, &headSize);
}

void TransTdcUnPackAllTlvDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    TcpDataTlvPacketHead head;
    (void)memset_s(&head, sizeof(TcpDataTlvPacketHead), 0, sizeof(TcpDataTlvPacketHead));
    FillTcpDataTlvPacketHead(provider, &head);
    uint32_t headSize = 0;
    DataBuf node;
    (void)memset_s(&node, sizeof(DataBuf), 0, sizeof(DataBuf));
    bool flag = false;

    (void)TransTdcUnPackAllTlvData(channelId, nullptr, nullptr, nullptr, nullptr);
    (void)TransTdcUnPackAllTlvData(channelId, &head, &headSize, &node, &flag);
}

void ReleaseDataHeadResourceTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));

    ReleaseDataHeadResource(&pktHead);
}

void TransTdcPackTlvDataTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));
    pktHead.magicNum = provider.ConsumeIntegral<uint32_t>();
    pktHead.tlvCount = provider.ConsumeIntegral<uint8_t>();
    int32_t tlvBufferSize = provider.ConsumeIntegralInRange<int32_t>(0, MAGICNUM_SIZE + TLVCOUNT_SIZE);
    uint32_t dataLen = provider.ConsumeIntegralInRange<uint32_t>(0, MAGICNUM_SIZE + TLVCOUNT_SIZE);

    (void)TransTdcPackTlvData(nullptr, tlvBufferSize, dataLen);
    (void)TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);

    tlvBufferSize = -(MAGICNUM_SIZE + TLVCOUNT_SIZE + dataLen);
    (void)TransTdcPackTlvData(&pktHead, tlvBufferSize, dataLen);
}

void BuildNeedAckTlvDataTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));
    pktHead.magicNum = provider.ConsumeIntegral<uint32_t>();
    pktHead.tlvCount = provider.ConsumeIntegral<uint8_t>();
    bool needAck = provider.ConsumeBool();
    uint32_t dataSeqs = provider.ConsumeIntegral<uint32_t>();
    int32_t tlvBufferSize = provider.ConsumeIntegral<int8_t>();

    (void)BuildNeedAckTlvData(nullptr, needAck, dataSeqs, &tlvBufferSize);
    (void)BuildNeedAckTlvData(&pktHead, needAck, dataSeqs, nullptr);
}

void BuildDataHeadTest(FuzzedDataProvider &provider)
{
    DataHead pktHead;
    (void)memset_s(&pktHead, sizeof(DataHead), 0, sizeof(DataHead));
    pktHead.magicNum = provider.ConsumeIntegral<uint32_t>();
    pktHead.tlvCount = provider.ConsumeIntegral<uint8_t>();
    int32_t finalSeq = provider.ConsumeIntegral<int32_t>();
    int32_t flags = provider.ConsumeIntegral<int32_t>();
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    int32_t tlvBufferSize = 0;

    (void)BuildDataHead(nullptr, finalSeq, flags, dataLen, nullptr);
    (void)BuildDataHead(&pktHead, finalSeq, flags, dataLen, &tlvBufferSize);
}

void TransTdcEncryptWithSeqTest(FuzzedDataProvider &provider)
{
    int32_t seqNum = provider.ConsumeIntegral<int32_t>();
    std::string sessionKey = provider.ConsumeRandomLengthString(UINT8_MAX);
    EncrptyInfo info;
    (void)memset_s(&info, sizeof(EncrptyInfo), 0, sizeof(EncrptyInfo));

    (void)TransTdcEncryptWithSeq(sessionKey.c_str(), seqNum, nullptr);
    (void)TransTdcEncryptWithSeq(sessionKey.c_str(), seqNum, &info);
}

void PackTcpDataPacketHeadTest(FuzzedDataProvider &provider)
{
    TcpDataPacketHead data;
    (void)memset_s(&data, sizeof(TcpDataPacketHead), 0, sizeof(TcpDataPacketHead));
    FillTcpDataPacketHead(provider, &data);

    (void)PackTcpDataPacketHead(&data);
}

void TransPackDataTest(FuzzedDataProvider &provider)
{
    uint32_t dataLen = provider.ConsumeIntegral<uint32_t>();
    int32_t finalSeq = provider.ConsumeIntegral<int32_t>();
    int32_t flags = provider.ConsumeIntegral<int32_t>();

    (void)TransPackData(dataLen, finalSeq, flags);
}

void BuildInnerTdcSendDataInfoTest(FuzzedDataProvider &provider)
{
    uint32_t inLen = provider.ConsumeIntegral<uint32_t>();
    EncrptyInfo info;
    (void)memset_s(&info, sizeof(EncrptyInfo), 0, sizeof(EncrptyInfo));

    BuildInnerTdcSendDataInfo(&info, nullptr, inLen, nullptr, nullptr);
}

static void FillTransTdcPackDataInfo(FuzzedDataProvider &provider, TransTdcPackDataInfo *info)
{
    info->needAck = provider.ConsumeBool();
    info->supportTlv = provider.ConsumeBool();
    info->seq = provider.ConsumeIntegral<int32_t>();
    info->len = provider.ConsumeIntegral<uint32_t>();
}

static void FillDataLenInfo(FuzzedDataProvider &provider, DataLenInfo *lenInfo)
{
    lenInfo->outLen = provider.ConsumeIntegral<uint32_t>();
    lenInfo->tlvHeadLen = provider.ConsumeIntegral<uint32_t>();
}

void TransTdcPackAllDataTest(FuzzedDataProvider &provider)
{
    TransTdcPackDataInfo info;
    (void)memset_s(&info, sizeof(TransTdcPackDataInfo), 0, sizeof(TransTdcPackDataInfo));
    FillTransTdcPackDataInfo(provider, &info);
    DataLenInfo lenInfo;
    (void)memset_s(&lenInfo, sizeof(DataLenInfo), 0, sizeof(DataLenInfo));
    FillDataLenInfo(provider, &lenInfo);
    std::string sessionKey = provider.ConsumeRandomLengthString(UINT8_MAX);
    std::string data = provider.ConsumeRandomLengthString(UINT8_MAX);
    int32_t flags = provider.ConsumeIntegral<int32_t>();

    (void)TransTdcPackAllData(nullptr, nullptr, nullptr, flags, nullptr);
    info.len = 0;
    (void)TransTdcPackAllData(&info, sessionKey.c_str(), data.c_str(), flags, &lenInfo);
    flags = FLAG_ACK;
    (void)TransTdcPackAllData(&info, sessionKey.c_str(), data.c_str(), flags, &lenInfo);
    info.supportTlv = true;
    (void)TransTdcPackAllData(&info, sessionKey.c_str(), data.c_str(), flags, &lenInfo);
}

void TransTdcSendDataTest(FuzzedDataProvider &provider)
{
    DataLenInfo lenInfo;
    (void)memset_s(&lenInfo, sizeof(DataLenInfo), 0, sizeof(DataLenInfo));
    FillDataLenInfo(provider, &lenInfo);
    bool supportTlv = provider.ConsumeBool();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    uint32_t len = provider.ConsumeIntegralInRange<uint32_t>(0, OVERHEAD_LEN);
    char buf[OVERHEAD_LEN] = { 0 };

    (void)TransTdcSendData(nullptr, supportTlv, fd, len, nullptr);
    fd = -1;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);

    lenInfo.outLen = len + OVERHEAD_LEN;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);
    supportTlv = true;
    (void)TransTdcSendData(&lenInfo, supportTlv, fd, len, buf);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransTcpProcessData testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::TransGetDataBufSizeTest(provider);
    OHOS::TransGetTdcDataBufMaxSizeTest(provider);
    OHOS::UnPackTcpDataPacketHeadTest(provider);
    OHOS::TransTcpDataTlvUnpackTest(provider);
    OHOS::TransResizeDataBufferTest(provider);
    OHOS::MoveNodeTest(provider);
    OHOS::TransTdcDecryptTest(provider);
    OHOS::TransTdcRecvFirstDataTest(provider);
    OHOS::TransTdcUnPackAllDataTest(provider);
    OHOS::TransTdcUnPackDataTest(provider);
    OHOS::CheckBufLenAndCopyDataTest(provider);
    OHOS::TransTdcParseTlvTest(provider);
    OHOS::TransTdcUnPackAllTlvDataTest(provider);
    OHOS::ReleaseDataHeadResourceTest(provider);
    OHOS::TransTdcPackTlvDataTest(provider);
    OHOS::BuildNeedAckTlvDataTest(provider);
    OHOS::BuildDataHeadTest(provider);
    OHOS::TransTdcEncryptWithSeqTest(provider);
    OHOS::PackTcpDataPacketHeadTest(provider);
    OHOS::TransPackDataTest(provider);
    OHOS::BuildInnerTdcSendDataInfoTest(provider);
    OHOS::TransTdcPackAllDataTest(provider);
    OHOS::TransTdcSendDataTest(provider);

    return 0;
}
