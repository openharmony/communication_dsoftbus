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

#include "transinner_fuzzer.h"

#include <cstring>
#include <fuzzer/FuzzedDataProvider.h>
#include <securec.h>
#include <vector>

#include "fuzz_data_generator.h"
#include "softbus_proxychannel_manager.h"
#include "trans_inner.c"

namespace OHOS {
class TransInner {
public:
    TransInner()
    {
        isInited_ = false;
        (void)TransProxyManagerInit(TransServerGetChannelCb());
        isInited_ = true;
    }

    ~TransInner()
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

void InnerListInitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)InnerListInit();
}

void InnerListDeinitTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)InnerListDeinit();
}

void ClientTransInnerTest(FuzzedDataProvider &provider)
{
    (void)provider;
    (void)InnerListInit();
    ClientTransInnerSliceListDeinit();
    ClientTransInnerDataBufDeinit();
    ClientTransInnerSessionDeinit();
}

void DirectChannelOnConnectEventTest(FuzzedDataProvider &provider)
{
    ListenerModule module = static_cast<ListenerModule>(provider.ConsumeIntegralInRange<uint16_t>(PROXY, UNUSE_BUTT));
    int32_t cfd = provider.ConsumeIntegral<int32_t>();
    ConnectOption clientAddr;
    (void)memset_s(&clientAddr, sizeof(ConnectOption), 0, sizeof(ConnectOption));

    (void)DirectChannelOnConnectEvent(module, cfd, &clientAddr);
}

void TransSrvDestroyDataBufTest(FuzzedDataProvider &provider)
{
    (void)provider;
    TransSrvDestroyDataBuf();
}

void TransSrvDelInnerDataBufNodeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    TransSrvDelInnerDataBufNode(channelId);
}

void TransInnerAddDataBufNodeTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t channelType = provider.ConsumeIntegralInRange<int16_t>(CHANNEL_TYPE_UNDEFINED, CHANNEL_TYPE_BUTT);

    (void)TransInnerAddDataBufNode(channelId, fd, channelType);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    (void)TransInnerAddDataBufNode(channelId, fd, channelType);
}

static int32_t TestInnerMessageHandler(int32_t sessionId, const void *data, uint32_t dataLen)
{
    (void)sessionId;
    (void)data;
    (void)dataLen;
    return SOFTBUS_OK;
}

void InnerAddSessionTest(FuzzedDataProvider &provider)
{
    InnerSessionInfo innerInfo;
    (void)memset_s(&innerInfo, sizeof(InnerSessionInfo), 0, sizeof(InnerSessionInfo));
    innerInfo.channelType = provider.ConsumeIntegralInRange<int16_t>(CHANNEL_TYPE_UNDEFINED, CHANNEL_TYPE_BUTT);
    SessionInnerCallback Innerlistener = { 0 };
    Innerlistener.func = TestInnerMessageHandler;
    innerInfo.listener = &Innerlistener;
    std::string sessionKey = provider.ConsumeRandomLengthString(SESSION_KEY_LENGTH);
    std::string peerNetworkId = provider.ConsumeRandomLengthString(NETWORK_ID_BUF_LEN);
    if (strcpy_s(innerInfo.sessionKey, SESSION_KEY_LENGTH, sessionKey.c_str()) != EOK ||
        strcpy_s(innerInfo.peerNetworkId, NETWORK_ID_BUF_LEN, peerNetworkId.c_str()) != EOK) {
        return;
    }

    innerInfo.channelType = CHANNEL_TYPE_TCP_DIRECT;
    (void)InnerAddSession(&innerInfo);
    innerInfo.channelType = CHANNEL_TYPE_PROXY;
    (void)InnerAddSession(&innerInfo);
}

void DirectOnChannelCloseTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerPkgName = provider.ConsumeBytesAsString(PKG_NAME_SIZE_MAX - 1);
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    if (strcpy_s(pkgName, PKG_NAME_SIZE_MAX, providerPkgName.c_str()) != EOK) {
        return;
    }

    DirectOnChannelClose(channelId, pkgName);
}

void TransCloseInnerSessionByNetworkIdTest(FuzzedDataProvider &provider)
{
    std::string providerNetworkId = provider.ConsumeBytesAsString(NETWORK_ID_BUF_LEN - 1);
    char networkId[NETWORK_ID_BUF_LEN] = { 0 };
    if (strcpy_s(networkId, NETWORK_ID_BUF_LEN, providerNetworkId.c_str()) != EOK) {
        return;
    }

    TransCloseInnerSessionByNetworkId(networkId);
}

void DeleteSessionTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)DeleteSession(fd, channelId);
}

void GetSessionInfoByFdTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));

    (void)GetSessionInfoByFd(fd, &info);
}

void GetSessionInfoByChanIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));

    (void)GetSessionInfoByChanId(channelId, &info);
}

void TransInnerGetTdcDataBufByIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();
    size_t len = 0;

    (void)TransInnerGetTdcDataBufById(channelId, fd, &len);
}

void TransInnerUpdateTdcDataBufWInfoTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int32_t recvLen = provider.ConsumeIntegralInRange<int32_t>(0, UINT8_MAX);
    char *recvBuf = reinterpret_cast<char *>(SoftBusCalloc(recvLen));
    if (recvBuf == nullptr) {
        return;
    }

    (void)TransInnerUpdateTdcDataBufWInfo(channelId, nullptr, recvLen);
    (void)TransInnerUpdateTdcDataBufWInfo(channelId, recvBuf, recvLen);
    SoftBusFree(recvBuf);
}

void TransGetInnerDataBufNodeByIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransGetInnerDataBufNodeById(channelId);
}

void TransTdcProcessInnerTlvDataTest(FuzzedDataProvider &provider)
{
    int32_t pkgHeadSize = provider.ConsumeIntegral<int32_t>();
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));
    TcpDataTlvPacketHead pktHead;
    (void)memset_s(&pktHead, sizeof(TcpDataTlvPacketHead), 0, sizeof(TcpDataTlvPacketHead));

    (void)TransTdcProcessInnerTlvData(&info, &pktHead, pkgHeadSize);
}

void TransInnerTdcProcAllTlvDataTest(FuzzedDataProvider &provider)
{
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));
    info.channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransInnerTdcProcAllTlvData(&info);
}

void TransTdcProcessInnerDataTest(FuzzedDataProvider &provider)
{
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));
    info.channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransTdcProcessInnerData(&info);
}

void TransInnerTdcProcAllDataTest(FuzzedDataProvider &provider)
{
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));
    info.channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransInnerTdcProcAllData(&info);
}

void TdcDataReceivedTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();

    (void)TdcDataReceived(fd);
}

void DirectChannelCloseSocketTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();

    DirectChannelCloseSocket(fd);
}

void DirectChannelOnDataEventTest(FuzzedDataProvider &provider)
{
    ListenerModule module = PROXY;
    int32_t events = provider.ConsumeIntegral<int32_t>();
    int32_t fd = provider.ConsumeIntegral<int32_t>();

    (void)DirectChannelOnDataEvent(module, events, fd);
}

void DirectChannelCreateListenerTest(FuzzedDataProvider &provider)
{
    int32_t fd = provider.ConsumeIntegral<int32_t>();

    (void)DirectChannelCreateListener(fd);
}

void TdcSendDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)TdcSendData(channelId, nullptr, len);
    (void)TdcSendData(channelId, reinterpret_cast<const void *>(data), len);
}

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

void ClientTransInnerProxyProcDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    DataHeadTlvPacketHead dataHead;
    (void)memset_s(&dataHead, sizeof(DataHeadTlvPacketHead), 0, sizeof(DataHeadTlvPacketHead));
    FillDataHeadTlvPacketHead(provider, &dataHead);

    (void)ClientTransInnerProxyProcData(channelId, &dataHead, data);
}

void ClientTransProxyInnerNoSubPacketTlvProcTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)ClientTransProxyInnerNoSubPacketTlvProc(channelId, data, len);
}

static void FillPacketHead(FuzzedDataProvider &provider, PacketHead *data)
{
    data->magicNumber = provider.ConsumeIntegral<int32_t>();
    data->seq = provider.ConsumeIntegral<int32_t>();
    data->flags = provider.ConsumeIntegral<int32_t>();
    data->dataLen = provider.ConsumeIntegral<int32_t>();
}

void ClientTransInnerProxyProcessSessionDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    PacketHead dataHead;
    (void)memset_s(&dataHead, sizeof(PacketHead), 0, sizeof(PacketHead));
    FillPacketHead(provider, &dataHead);

    (void)ClientTransInnerProxyProcessSessionData(channelId, &dataHead, data);
}

void ClientTransInnerProxyNoSubPacketProcTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)ClientTransInnerProxyNoSubPacketProc(channelId, data, len);
}

void ClientTransProxyGetChannelSliceTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)ClientTransProxyGetChannelSlice(channelId);
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

static void FillSliceHead(FuzzedDataProvider &provider, SliceHead *data)
{
    data->priority = provider.ConsumeIntegral<int32_t>();
    data->sliceNum = provider.ConsumeIntegral<int32_t>();
    data->sliceSeq = provider.ConsumeIntegral<int32_t>();
    data->reserved = provider.ConsumeIntegral<int32_t>();
}

void ClientTransInnerProxyFirstSliceProcessTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);

    (void)ClientTransInnerProxyFirstSliceProcess(&processor, &head, data, len, channelId);
}

void IsValidCheckoutSliceProcessTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)IsValidCheckoutSliceProcess(channelId);
}

void ClientTransProxyLastSliceProcessTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    SliceProcessor processor;
    (void)memset_s(&processor, sizeof(SliceProcessor), 0, sizeof(SliceProcessor));
    FillSliceProcessor(provider, &processor);
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);

    (void)ClientTransProxyLastSliceProcess(&processor, &head, data, len, channelId);
}

void TransProxyDelSliceProcessorByChannelIdTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    (void)TransProxyDelSliceProcessorByChannelId(channelId);
}

void ClientTransProxySubPacketProcTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    SliceHead head;
    (void)memset_s(&head, sizeof(SliceHead), 0, sizeof(SliceHead));
    FillSliceHead(provider, &head);

    (void)ClientTransProxySubPacketProc(channelId, &head, nullptr, len);
}

void ProxyDataRecvHandlerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)ProxyDataRecvHandler(channelId, nullptr, len);
    (void)ProxyDataRecvHandler(channelId, data, len);
}

void TransInnerProxyPackBytesTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    ProxyDataInfo dataInfo;
    (void)memset_s(&dataInfo, sizeof(ProxyDataInfo), 0, sizeof(ProxyDataInfo));
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));

    (void)TransInnerProxyPackBytes(channelId, nullptr, nullptr);
    (void)TransInnerProxyPackBytes(channelId, &dataInfo, &info);
}

void ProxySendDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();
    TransInnerSessionInfo info;
    (void)memset_s(&info, sizeof(TransInnerSessionInfo), 0, sizeof(TransInnerSessionInfo));

    (void)ProxySendData(channelId, data, len, nullptr);
    (void)ProxySendData(channelId, nullptr, len, &info);
}

void TransSendDataTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    std::string providerData = provider.ConsumeBytesAsString(UINT8_MAX - 1);
    char data[UINT8_MAX] = { 0 };
    if (strcpy_s(data, UINT8_MAX, providerData.c_str()) != EOK) {
        return;
    }
    uint32_t len = provider.ConsumeIntegral<uint32_t>();

    (void)TransSendData(channelId, reinterpret_cast<const void *>(data), len);
}

void CloseSessionInnerTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();

    CloseSessionInner(channelId);
}

void GetSessionInfoTest(FuzzedDataProvider &provider)
{
    int32_t channelId = provider.ConsumeIntegral<int32_t>();
    int fd = 0;
    int channelType = 0;
    char sessionKey[SESSION_KEY_LENGTH] = { 0 };
    int32_t keyLen = SESSION_KEY_LENGTH;

    (void)GetSessionInfo(channelId, &fd, &channelType, sessionKey, keyLen);
}

void ServerSideSendAckTest(FuzzedDataProvider &provider)
{
    int32_t sessionId = provider.ConsumeIntegral<int32_t>();
    int32_t result = provider.ConsumeIntegral<int32_t>();

    (void)ServerSideSendAck(sessionId, result);
}
} // namespace OHOS

/* Fuzzer entry point */
extern "C" int32_t LLVMFuzzerTestOneInput(const uint8_t *data, size_t size)
{
    static OHOS::TransInner testEvent;
    if (!testEvent.IsInited()) {
        return 0;
    }

    /* Run your code on data */
    FuzzedDataProvider provider(data, size);
    OHOS::ClientTransInnerTest(provider);
    OHOS::InnerListInitTest(provider);
    OHOS::DirectChannelOnConnectEventTest(provider);
    OHOS::TransSrvDestroyDataBufTest(provider);
    OHOS::TransSrvDelInnerDataBufNodeTest(provider);
    OHOS::TransInnerAddDataBufNodeTest(provider);
    OHOS::InnerAddSessionTest(provider);
    OHOS::DirectOnChannelCloseTest(provider);
    OHOS::TransCloseInnerSessionByNetworkIdTest(provider);
    OHOS::DeleteSessionTest(provider);
    OHOS::GetSessionInfoByFdTest(provider);
    OHOS::GetSessionInfoByChanIdTest(provider);
    OHOS::TransInnerGetTdcDataBufByIdTest(provider);
    OHOS::TransInnerUpdateTdcDataBufWInfoTest(provider);
    OHOS::TransGetInnerDataBufNodeByIdTest(provider);
    OHOS::DirectChannelCloseSocketTest(provider);
    OHOS::DirectChannelCreateListenerTest(provider);
    OHOS::ClientTransProxyGetChannelSliceTest(provider);
    OHOS::IsValidCheckoutSliceProcessTest(provider);
    OHOS::TransProxyDelSliceProcessorByChannelIdTest(provider);
    OHOS::CloseSessionInnerTest(provider);
    OHOS::GetSessionInfoTest(provider);
    OHOS::ServerSideSendAckTest(provider);
    OHOS::InnerListDeinitTest(provider);

    return 0;
}
