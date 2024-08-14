/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#ifndef TRANS_TCP_DIRECT_P2P_TEST_MOCK_H
#define TRANS_TCP_DIRECT_P2P_TEST_MOCK_H

#include <gmock/gmock.h>
#include "cJSON.h"
#include "auth_interface.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_proxychannel_pipeline.h"
#include "trans_tcp_direct_sessionconn.h"

namespace OHOS {
class TransTcpDirectP2pInterface {
public:
    TransTcpDirectP2pInterface() {};
    virtual ~TransTcpDirectP2pInterface() {};
    virtual int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info) = 0;
    virtual SoftBusList *CreateSoftBusList() = 0;
    virtual int32_t StopBaseListener(ListenerModule module) = 0;
    virtual bool IsHmlIpAddr(const char *ip) = 0;
    virtual int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener) = 0;
    virtual int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type,
        const ITransProxyPipelineListener *listener) = 0;
    virtual int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo) = 0;
    virtual char *VerifyP2pPack(const char *myIp, int32_t myPort, const char *peerIp) = 0;
    virtual int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode) = 0;
    virtual int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta) = 0;
    virtual int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta) = 0;
    virtual char *VerifyP2pPackError(int32_t code, int32_t errCode, const char *errDesc) = 0;
    virtual int32_t TransProxyPipelineSendMessage(int32_t channelId, const uint8_t *data,
        uint32_t dataLen, TransProxyPipelineMsgType type) = 0;
    virtual int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock) = 0;
    virtual int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
    virtual int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd) = 0;
    virtual cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length) = 0;
    virtual int32_t TransProxyPipelineGetChannelIdByNetworkId(const char *networkId) = 0;
    virtual uint32_t AuthGenRequestId() = 0;
    virtual int32_t TransProxyReuseByChannelId(int32_t channelId) = 0;
    virtual int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId) = 0;
    virtual SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid) = 0;
};

class TransTcpDirectP2pInterfaceMock : public TransTcpDirectP2pInterface {
public:
    TransTcpDirectP2pInterfaceMock();
    ~TransTcpDirectP2pInterfaceMock() override;
    MOCK_METHOD2(TransTdcStartSessionListener, int32_t (ListenerModule module, const LocalListenerInfo *info));
    MOCK_METHOD0(CreateSoftBusList, SoftBusList *());
    MOCK_METHOD1(StopBaseListener, int32_t (ListenerModule module));
    MOCK_METHOD1(IsHmlIpAddr, bool (const char *ip));
    MOCK_METHOD2(RegAuthTransListener, int32_t (int32_t module, const AuthTransListener *listener));
    MOCK_METHOD2(TransProxyPipelineRegisterListener, int32_t (TransProxyPipelineMsgType type,
        const ITransProxyPipelineListener *listener));
    MOCK_METHOD2(AuthPostTransData, int32_t (AuthHandle authHandle, const AuthTransData *dataInfo));
    MOCK_METHOD3(VerifyP2pPack, char *(const char *myIp, int32_t myPort, const char *peerIp));
    MOCK_METHOD2(NotifyChannelOpenFailed, int32_t (int32_t channelId, int32_t errCode));
    MOCK_METHOD3(AuthGetHmlConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD3(AuthGetP2pConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD3(AuthGetPreferConnInfo, int32_t (const char *uuid, AuthConnInfo *connInfo, bool isMeta));
    MOCK_METHOD4(AuthOpenConn, int32_t (const AuthConnInfo *info, uint32_t requestId,
        const AuthConnCallback *callback, bool isMeta));
    MOCK_METHOD3(VerifyP2pPackError, char *(int32_t code, int32_t errCode, const char *errDesc));
    MOCK_METHOD4(TransProxyPipelineSendMessage, int32_t (int32_t channelId, const uint8_t *data,
        uint32_t dataLen, TransProxyPipelineMsgType type));
    MOCK_METHOD3(ConnOpenClientSocket, int32_t (const ConnectOption *option, const char *bindAddr, bool isNonBlock));
    MOCK_METHOD3(AddTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
    MOCK_METHOD2(TransSrvAddDataBufNode, int32_t (int32_t channelId, int32_t fd));
    MOCK_METHOD2(cJSON_ParseWithLength, cJSON *(const char *value, size_t buffer_length));
    MOCK_METHOD1(TransProxyPipelineGetChannelIdByNetworkId, int32_t (const char *networkId));
    MOCK_METHOD0(AuthGenRequestId, uint32_t ());
    MOCK_METHOD1(TransProxyReuseByChannelId, int32_t (int32_t channelId));
    MOCK_METHOD1(TransProxyPipelineCloseChannelDelay, int32_t (int32_t channelId));
    MOCK_METHOD2(CreateNewSessinConn, SessionConn *(ListenerModule module, bool isServerSid));
};
} // namespace OHOS
#endif // TRANS_TCP_DIRECT_P2P_TEST_MOCK_H
