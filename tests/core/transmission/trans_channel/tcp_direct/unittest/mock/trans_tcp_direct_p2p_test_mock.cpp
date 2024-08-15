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

#include "trans_tcp_direct_p2p_test_mock.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {
void *g_transTcpDirectP2pInterface;
TransTcpDirectP2pInterfaceMock::TransTcpDirectP2pInterfaceMock()
{
    g_transTcpDirectP2pInterface = reinterpret_cast<void *>(this);
}

TransTcpDirectP2pInterfaceMock::~TransTcpDirectP2pInterfaceMock()
{
    g_transTcpDirectP2pInterface = nullptr;
}

static TransTcpDirectP2pInterface *GetTransTcpDirectP2pInterface()
{
    return reinterpret_cast<TransTcpDirectP2pInterface *>(g_transTcpDirectP2pInterface);
}

extern "C" {
int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info)
{
    return GetTransTcpDirectP2pInterface()->TransTdcStartSessionListener(module, info);
}

SoftBusList *CreateSoftBusList()
{
    return GetTransTcpDirectP2pInterface()->CreateSoftBusList();
}

int32_t StopBaseListener(ListenerModule module)
{
    return GetTransTcpDirectP2pInterface()->StopBaseListener(module);
}

bool IsHmlIpAddr(const char *ip)
{
    return GetTransTcpDirectP2pInterface()->IsHmlIpAddr(ip);
}

int32_t RegAuthTransListener(int32_t module, const AuthTransListener *listener)
{
    return GetTransTcpDirectP2pInterface()->RegAuthTransListener(module, listener);
}

int32_t TransProxyPipelineRegisterListener(TransProxyPipelineMsgType type, const ITransProxyPipelineListener *listener)
{
    return GetTransTcpDirectP2pInterface()->TransProxyPipelineRegisterListener(type, listener);
}

int32_t AuthPostTransData(AuthHandle authHandle, const AuthTransData *dataInfo)
{
    return GetTransTcpDirectP2pInterface()->AuthPostTransData(authHandle, dataInfo);
}

char *VerifyP2pPack(const char *myIp, int32_t myPort, const char *peerIp)
{
    return GetTransTcpDirectP2pInterface()->VerifyP2pPack(myIp, myPort, peerIp);
}

int32_t NotifyChannelOpenFailed(int32_t channelId, int32_t errCode)
{
    return GetTransTcpDirectP2pInterface()->NotifyChannelOpenFailed(channelId, errCode);
}

int32_t AuthGetHmlConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransTcpDirectP2pInterface()->AuthGetHmlConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetP2pConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransTcpDirectP2pInterface()->AuthGetP2pConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo, bool isMeta)
{
    return GetTransTcpDirectP2pInterface()->AuthGetPreferConnInfo(uuid, connInfo, isMeta);
}

int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback, bool isMeta)
{
    return GetTransTcpDirectP2pInterface()->AuthOpenConn(info, requestId, callback, isMeta);
}

char *VerifyP2pPackError(int32_t code, int32_t errCode, const char *errDesc)
{
    return GetTransTcpDirectP2pInterface()->VerifyP2pPackError(code, errCode, errDesc);
}

int32_t TransProxyPipelineSendMessage(int32_t channelId, const uint8_t *data,
    uint32_t dataLen, TransProxyPipelineMsgType type)
{
    return GetTransTcpDirectP2pInterface()->TransProxyPipelineSendMessage(channelId, data, dataLen, type);
}

int32_t ConnOpenClientSocket(const ConnectOption *option, const char *bindAddr, bool isNonBlock)
{
    return GetTransTcpDirectP2pInterface()->ConnOpenClientSocket(option, bindAddr, isNonBlock);
}

int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger)
{
    return GetTransTcpDirectP2pInterface()->AddTrigger(module, fd, trigger);
}

int32_t TransSrvAddDataBufNode(int32_t channelId, int32_t fd)
{
    return GetTransTcpDirectP2pInterface()->TransSrvAddDataBufNode(channelId, fd);
}

cJSON *cJSON_ParseWithLength(const char *value, size_t buffer_length)
{
    return GetTransTcpDirectP2pInterface()->cJSON_ParseWithLength(value, buffer_length);
}

int32_t TransProxyPipelineGetChannelIdByNetworkId(const char *networkId)
{
    return GetTransTcpDirectP2pInterface()->TransProxyPipelineGetChannelIdByNetworkId(networkId);
}

uint32_t AuthGenRequestId()
{
    return GetTransTcpDirectP2pInterface()->AuthGenRequestId();
}

int32_t TransProxyReuseByChannelId(int32_t channelId)
{
    return GetTransTcpDirectP2pInterface()->TransProxyReuseByChannelId(channelId);
}

int32_t TransProxyPipelineCloseChannelDelay(int32_t channelId)
{
    return GetTransTcpDirectP2pInterface()->TransProxyPipelineCloseChannelDelay(channelId);
}

SessionConn *CreateNewSessinConn(ListenerModule module, bool isServerSid)
{
    return GetTransTcpDirectP2pInterface()->CreateNewSessinConn(module, isServerSid);
}
}
}
