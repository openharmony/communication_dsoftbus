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

#include "trans_inner_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transInnerInterface = nullptr;
TransInnerInterfaceMock::TransInnerInterfaceMock()
{
    g_transInnerInterface = reinterpret_cast<void *>(this);
}

TransInnerInterfaceMock::~TransInnerInterfaceMock()
{
    g_transInnerInterface = nullptr;
}

static TransInnerInterface *GetTransInnerInterface()
{
    return reinterpret_cast<TransInnerInterface *>(g_transInnerInterface);
}

extern "C" {
int32_t ClientIpcOnChannelClosed(ChannelMsg *data)
{
    return GetTransInnerInterface()->ClientIpcOnChannelClosed(data);
}

int32_t TransProxyGetAppInfoByChanId(int32_t chanId, AppInfo *appInfo)
{
    return GetTransInnerInterface()->TransProxyGetAppInfoByChanId(chanId, appInfo);
}

int32_t TransTdcDecrypt(const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    return GetTransInnerInterface()->TransTdcDecrypt(sessionKey, in, inLen, out, outLen);
}

int32_t MoveNode(int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize)
{
    return GetTransInnerInterface()->MoveNode(channelId, node, dataLen, pkgHeadSize);
}

int32_t TransTdcUnPackAllTlvData(
    int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag)
{
    return GetTransInnerInterface()->TransTdcUnPackAllTlvData(channelId, head, headSize, node, flag);
}

int32_t TransTdcUnPackAllData(int32_t channelId, DataBuf *node, bool *flag)
{
    return GetTransInnerInterface()->TransTdcUnPackAllData(channelId, node, flag);
}

int32_t TransTdcRecvFirstData(int32_t channelId, char *recvBuf, int32_t *recvLen, int32_t fd, size_t len)
{
    return GetTransInnerInterface()->TransTdcRecvFirstData(channelId, recvBuf, recvLen, fd, len);
}

int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType, bool isAsync)
{
    return GetTransInnerInterface()->TransLaneMgrDelLane(channelId, channelType, isAsync);
}

int32_t TransDelTcpChannelInfoByChannelId(int32_t channelId)
{
    return GetTransInnerInterface()->TransDelTcpChannelInfoByChannelId(channelId);
}

int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetTransInnerInterface()->DelTrigger(module, fd, trigger);
}

int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how)
{
    return GetTransInnerInterface()->SoftBusSocketShutDown(socketFd, how);
}

int32_t SoftBusSocketClose(int32_t socketFd)
{
    return GetTransInnerInterface()->SoftBusSocketClose(socketFd);
}

uint32_t CreateListenerModule(void)
{
    return GetTransInnerInterface()->CreateListenerModule();
}

int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener)
{
    return GetTransInnerInterface()->StartBaseClient(module, listener);
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetTransInnerInterface()->AddTrigger(module, fd, trigger);
}

char *TransTdcPackAllData(
    TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo)
{
    return GetTransInnerInterface()->TransTdcPackAllData(info, sessionKey, data, flags, lenInfo);
}

int32_t SetIpTos(int fd, uint32_t tos)
{
    return GetTransInnerInterface()->SetIpTos(fd, tos);
}

int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf)
{
    return GetTransInnerInterface()->TransTdcSendData(lenInfo, supportTlv, fd, len, buf);
}

int32_t TransProxyProcData(ProxyDataInfo *dataInfo, const DataHeadTlvPacketHead *dataHead, const char *data)
{
    return GetTransInnerInterface()->TransProxyProcData(dataInfo, dataHead, data);
}

int32_t TransProxyParseTlv(uint32_t len, const char *data, DataHeadTlvPacketHead *head, uint32_t *headSize)
{
    return GetTransInnerInterface()->TransProxyParseTlv(len, data, head, headSize);
}

int32_t TransProxyNoSubPacketTlvProc(
    int32_t channelId, const char *data, uint32_t len, DataHeadTlvPacketHead *pktHead, uint32_t newPktHeadSize)
{
    return GetTransInnerInterface()->TransProxyNoSubPacketTlvProc(channelId, data, len, pktHead, newPktHeadSize);
}

int32_t TransProxyProcessSessionData(ProxyDataInfo *dataInfo, const PacketHead *dataHead, const char *data)
{
    return GetTransInnerInterface()->TransProxyProcessSessionData(dataInfo, dataHead, data);
}

int32_t TransProxySliceProcessChkPkgIsValid(
    const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    return GetTransInnerInterface()->TransProxySliceProcessChkPkgIsValid(processor, head, data, len);
}

int32_t TransProxyNormalSliceProcess(SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len)
{
    return GetTransInnerInterface()->TransProxyNormalSliceProcess(processor, head, data, len);
}

int32_t TransProxyPackTlvBytes(
    ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info)
{
    return GetTransInnerInterface()->TransProxyPackTlvBytes(dataInfo, sessionKey, flag, seq, info);
}

int32_t TransProxyPackBytes(
    int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq)
{
    return GetTransInnerInterface()->TransProxyPackBytes(channelId, dataInfo, sessionKey, flag, seq);
}

int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo)
{
    return GetTransInnerInterface()->GetAppInfoById(channelId, appInfo);
}

int32_t TransDealTdcChannelOpenResult(int32_t channelId, int32_t openResult)
{
    return GetTransInnerInterface()->TransDealTdcChannelOpenResult(channelId, openResult);
}

int32_t TransDealProxyChannelOpenResult(int32_t channelId, int32_t openResult)
{
    return GetTransInnerInterface()->TransDealProxyChannelOpenResult(channelId, openResult);
}
}
}
