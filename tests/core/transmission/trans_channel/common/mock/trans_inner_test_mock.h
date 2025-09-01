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

#ifndef TRANS_INNER_TEST_MOCK_H
#define TRANS_INNER_TEST_MOCK_H

#include <gmock/gmock.h>
#include "softbus_app_info.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "trans_client_proxy.h"
#include "trans_tcp_process_data.h"
#include "trans_proxy_process_data.h"

namespace OHOS {
class TransInnerInterface {
public:
    TransInnerInterface() {};
    virtual ~TransInnerInterface() {};
    virtual int32_t ClientIpcOnChannelClosed(ChannelMsg *data) = 0;
    virtual int32_t TransProxyGetAppInfoByChanId(int32_t chanId, AppInfo *appInfo) = 0;
    virtual int32_t TransTdcDecrypt(
        const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen) = 0;
    virtual int32_t MoveNode(int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize) = 0;
    virtual int32_t TransTdcUnPackAllTlvData(
        int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag) = 0;
    virtual int32_t TransTdcUnPackAllData(int32_t channelId, DataBuf *node, bool *flag) = 0;
    virtual int32_t TransTdcRecvFirstData(
        int32_t channelId, char *recvBuf, int32_t *recvLen, int32_t fd, size_t len) = 0;
    virtual int32_t TransLaneMgrDelLane(int32_t channelId, int32_t channelType, bool isAsync) = 0;
    virtual int32_t TransDelTcpChannelInfoByChannelId(int32_t channelId) = 0;
    virtual int32_t DelTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
    virtual int32_t SoftBusSocketShutDown(int32_t socketFd, int32_t how) = 0;
    virtual int32_t SoftBusSocketClose(int32_t socketFd) = 0;
    virtual uint32_t CreateListenerModule(void) = 0;
    virtual int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener) = 0;
    virtual int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
    virtual char *TransTdcPackAllData(
        TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo) = 0;
    virtual int32_t SetIpTos(int fd, uint32_t tos) = 0;
    virtual int32_t TransTdcSendData(DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf) = 0;
    virtual int32_t TransProxyProcData(
        ProxyDataInfo *dataInfo, const DataHeadTlvPacketHead *dataHead, const char *data) = 0;
    virtual int32_t TransProxyParseTlv(
        uint32_t len, const char *data, DataHeadTlvPacketHead *head, uint32_t *headSize) = 0;
    virtual int32_t TransProxyNoSubPacketTlvProc(int32_t channelId,
        uint32_t len, DataHeadTlvPacketHead *pktHead, uint32_t newPktHeadSize) = 0;
    virtual int32_t TransProxyProcessSessionData(
        ProxyDataInfo *dataInfo, const PacketHead *dataHead, const char *data) = 0;
    virtual int32_t TransProxySliceProcessChkPkgIsValid(
        const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len) = 0;
    virtual int32_t TransProxyNormalSliceProcess(
        SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len) = 0;
    virtual int32_t TransProxyPackTlvBytes(ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info) = 0;
    virtual int32_t TransProxyPackBytes(
        int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq) = 0;
    virtual int32_t GetAppInfoById(int32_t channelId, AppInfo *appInfo) = 0;
    virtual int32_t TransDealTdcChannelOpenResult(int32_t channelId, int32_t openResult) = 0;
    virtual int32_t TransDealProxyChannelOpenResult(int32_t channelId, int32_t openResult) = 0;
};

class TransInnerInterfaceMock : public TransInnerInterface {
public:
    TransInnerInterfaceMock();
    ~TransInnerInterfaceMock() override;
    MOCK_METHOD1(ClientIpcOnChannelClosed, int32_t (ChannelMsg *data));
    MOCK_METHOD2(TransProxyGetAppInfoByChanId, int32_t (int32_t chanId, AppInfo *appInfo));
    MOCK_METHOD5(TransTdcDecrypt, int32_t (
        const char *sessionKey, const char *in, uint32_t inLen, char *out, uint32_t *outLen));
    MOCK_METHOD4(MoveNode, int32_t (int32_t channelId, DataBuf *node, uint32_t dataLen, int32_t pkgHeadSize));
    MOCK_METHOD5(TransTdcUnPackAllTlvData, int32_t (
        int32_t channelId, TcpDataTlvPacketHead *head, uint32_t *headSize, DataBuf *node, bool *flag));
    MOCK_METHOD3(TransTdcUnPackAllData, int32_t (int32_t channelId, DataBuf *node, bool *flag));
    MOCK_METHOD5(TransTdcRecvFirstData, int32_t (
        int32_t channelId, char *recvBuf, int32_t *recvLen, int32_t fd, size_t len));
    MOCK_METHOD3(TransLaneMgrDelLane, int32_t (int32_t channelId, int32_t channelType, bool isAsync));
    MOCK_METHOD1(TransDelTcpChannelInfoByChannelId, int32_t (int32_t channelId));
    MOCK_METHOD3(DelTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
    MOCK_METHOD2(SoftBusSocketShutDown, int32_t (int32_t socketFd, int32_t how));
    MOCK_METHOD1(SoftBusSocketClose, int32_t (int32_t socketFd));
    MOCK_METHOD0(CreateListenerModule, uint32_t ());
    MOCK_METHOD2(StartBaseClient, int32_t (ListenerModule module, const SoftbusBaseListener *listener));
    MOCK_METHOD3(AddTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
    MOCK_METHOD5(TransTdcPackAllData, char *(
        TransTdcPackDataInfo *info, const char *sessionKey, const char *data, int32_t flags, DataLenInfo *lenInfo));
    MOCK_METHOD2(SetIpTos, int32_t (int fd, uint32_t tos));
    MOCK_METHOD5(TransTdcSendData, int32_t (
        DataLenInfo *lenInfo, bool supportTlv, int32_t fd, uint32_t len, char *buf));
    MOCK_METHOD3(TransProxyProcData, int32_t (
        ProxyDataInfo *dataInfo, const DataHeadTlvPacketHead *dataHead, const char *data));
    MOCK_METHOD4(TransProxyParseTlv, int32_t (
        uint32_t len, const char *data, DataHeadTlvPacketHead *head, uint32_t *headSize));
    MOCK_METHOD4(TransProxyNoSubPacketTlvProc, int32_t (
        int32_t channelId, uint32_t len, DataHeadTlvPacketHead *pktHead, uint32_t newPktHeadSize));
    MOCK_METHOD3(TransProxyProcessSessionData, int32_t (
        ProxyDataInfo *dataInfo, const PacketHead *dataHead, const char *data));
    MOCK_METHOD4(TransProxySliceProcessChkPkgIsValid, int32_t (
        const SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len));
    MOCK_METHOD4(TransProxyNormalSliceProcess, int32_t (
        SliceProcessor *processor, const SliceHead *head, const char *data, uint32_t len));
    MOCK_METHOD5(TransProxyPackTlvBytes, int32_t (ProxyDataInfo *dataInfo, const char *sessionKey,
        SessionPktType flag, int32_t seq, DataHeadTlvPacketHead *info));
    MOCK_METHOD5(TransProxyPackBytes, int32_t (
        int32_t channelId, ProxyDataInfo *dataInfo, const char *sessionKey, SessionPktType flag, int32_t seq));
    MOCK_METHOD2(GetAppInfoById, int32_t (int32_t channelId, AppInfo *appInfo));
    MOCK_METHOD2(TransDealTdcChannelOpenResult, int32_t (int32_t channelId, int32_t openResult));
    MOCK_METHOD2(TransDealProxyChannelOpenResult, int32_t (int32_t channelId, int32_t openResult));
};
} // namespace OHOS
#endif // TRANS_INNER_TEST_MOCK_H
