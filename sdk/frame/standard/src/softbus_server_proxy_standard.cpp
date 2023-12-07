/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "softbus_server_proxy_standard.h"

#include "comm_log.h"
#include "message_parcel.h"
#include "softbus_client_stub.h"
#include "softbus_errcode.h"
#include "softbus_server_ipc_interface_code.h"

namespace OHOS {
sptr<IRemoteObject> SoftBusServerProxyFrame::clientCallbackStub_;
std::mutex SoftBusServerProxyFrame::instanceLock;

sptr<IRemoteObject> SoftBusServerProxyFrame::GetRemoteInstance()
{
    if (clientCallbackStub_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock);
        if (clientCallbackStub_ == nullptr) {
            clientCallbackStub_ = sptr<IRemoteObject>(new (std::nothrow) SoftBusClientStub());
        }
    }
    return clientCallbackStub_;
}

int32_t SoftBusServerProxyFrame::StartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    (void)pkgName;
    (void)info;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::StopDiscovery(const char *pkgName, int subscribeId)
{
    (void)pkgName;
    (void)subscribeId;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::PublishService(const char *pkgName, const PublishInfo *info)
{
    (void)pkgName;
    (void)info;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::UnPublishService(const char *pkgName, int publishId)
{
    (void)pkgName;
    (void)publishId;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    sptr<IRemoteObject> remote = Remote();
    if (remote == nullptr) {
        COMM_LOGE(COMM_SDK, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    sptr<IRemoteObject> clientStub = SoftBusServerProxyFrame::GetRemoteInstance();
    if (clientStub == nullptr) {
        COMM_LOGE(COMM_SDK, "client stub is nullptr!");
        return SOFTBUS_ERR;
    }
    MessageParcel data;
    if (!data.WriteInterfaceToken(GetDescriptor())) {
        COMM_LOGE(COMM_SDK, "SoftbusRegisterService write InterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRemoteObject(clientStub)) {
        COMM_LOGE(COMM_SDK, "SoftbusRegisterService write remote object failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(clientPkgName)) {
        COMM_LOGE(COMM_SDK, "SoftbusRegisterService write clientPkgName failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(MANAGE_REGISTER_SERVICE, data, reply, option);
    if (err != 0) {
        COMM_LOGE(COMM_SDK, "SoftbusRegisterService send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        COMM_LOGE(COMM_SDK, "SoftbusRegisterService read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t SoftBusServerProxyFrame::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    (void)pkgName;
    (void)sessionName;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::OpenSession(const SessionParam *param, TransInfo *info)
{
    (void)param;
    (void)info;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    (void)sessionName;
    (void)addrInfo;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::CloseChannel(int32_t channelId, int32_t channelType)
{
    (void)channelId;
    (void)channelType;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    (void)len;
    (void)msgType;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    (void)pkgName;
    (void)addr;
    (void)addrTypeLen;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::LeaveLNN(const char *pkgName, const char *networkId)
{
    (void)pkgName;
    (void)networkId;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen,
    int *infoNum)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)infoNum;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key,
    unsigned char *buf, uint32_t len)
{
    (void)pkgName;
    (void)networkId;
    (void)key;
    (void)buf;
    (void)len;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::SetNodeDataChangeFlag(const char *pkgName, const char *networkId,
    uint16_t dataChangeFlag)
{
    (void)pkgName;
    (void)networkId;
    (void)dataChangeFlag;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    (void)pkgName;
    (void)targetNetworkId;
    (void)accuracy;
    (void)period;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    (void)pkgName;
    (void)targetNetworkId;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    (void)channelId;
    (void)chanType;
    (void)appType;
    (void)quality;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    (void)channelId;
    (void)channelType;
    (void)data;
    return SOFTBUS_OK;
}

int32_t SoftBusServerProxyFrame::EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
    uint32_t qosCount)
{
    (void)peerNetworkId;
    (void)dataType;
    (void)qos;
    (void)qosCount;
    return SOFTBUS_OK;
}
} // namespace OHOS