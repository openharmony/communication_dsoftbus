/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "bus_center_server_proxy_standard.h"

#include <securec.h>
#include "bus_center_server_proxy.h"
#include "discovery_service.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "message_parcel.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "system_ability_definition.h"

namespace OHOS {

static uint32_t g_getSystemAbilityId = 2;
static sptr<IRemoteObject> GetSystemAbility()
{
    MessageParcel data;
    data.WriteInt32(SOFTBUS_SERVER_SA_ID);
    MessageParcel reply;
    MessageOption option;
    sptr<IRemoteObject> samgr = IPCSkeleton::GetContextObject();
    int32_t err = samgr->SendRequest(g_getSystemAbilityId, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "Get GetSystemAbility failed!\n");
        return nullptr;
    }
    return reply.ReadRemoteObject();
}

int32_t BusCenterServerProxy::StartDiscovery(const char *pkgName, const SubscribeInfo *subInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StopDiscovery(const char *pkgName, int subscribeId)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::PublishService(const char *pkgName, const PublishInfo *pubInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::UnPublishService(const char *pkgName, int publishId)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject>& object)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenSession(const SessionParam* param, TransInfo* info)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::NotifyAuthSuccess(int channelId)
{
    return SOFTBUS_OK;    
}

int32_t BusCenterServerProxy::CloseChannel(int32_t channelId, int32_t channelType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    if (pkgName == nullptr || addr == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write addr type length failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN write addr failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_LNN, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "JoinLNN read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::LeaveLNN(const char *pkgName, const char *networkId)
{
    if (pkgName == nullptr || networkId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN write networkId failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_LNN, data, reply, option);
    if (err != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "LeaveLNN read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    if (info == nullptr || infoNum == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo send request failed!");
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(*infoNum)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo read infoNum failed!");
        return SOFTBUS_ERR;
    }
    int32_t infoSize = (*infoNum) * (int32_t)infoTypeLen;
    *info = nullptr;
    if (infoSize > 0) {
        void *nodeInfo = (void *)reply.ReadRawData(infoSize);
        if (nodeInfo == nullptr) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo read node info failed!");
            return SOFTBUS_ERR;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == nullptr) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo malloc failed!");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(*info, infoSize, nodeInfo, infoSize) != EOK) {
            SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetAllOnlineNodeInfo copy node info failed!");
            SoftBusFree(*info);
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    if (info == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *nodeInfo = (void *)reply.ReadRawData(infoTypeLen);
    if (nodeInfo == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo read node info failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info, infoTypeLen, nodeInfo, infoTypeLen) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetLocalDeviceInfo copy node info failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    if (networkId == nullptr || buf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "params are nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write networkId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(key)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write key failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(len)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo write buf len failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_NODE_KEY_INFO, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *retBuf = (void *)reply.ReadRawData(len);
    if (retBuf == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo read retBuf failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(buf, len, retBuf, len) != EOK) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "GetNodeKeyInfo copy node key info failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write client name failed!");
        return SOFTBUS_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write networkId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(accuracy)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write accuracy failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(period)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync write period failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_START_TIME_SYNC, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StartTimeSync read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}

int32_t BusCenterServerProxy::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    if (pkgName == nullptr || targetNetworkId == nullptr) {
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync write client name failed!");
        return SOFTBUS_ERR;
    }

    if (!data.WriteCString(targetNetworkId)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync write networkId failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_STOP_TIME_SYNC, data, reply, option) != 0) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        SoftBusLog(SOFTBUS_LOG_LNN, SOFTBUS_LOG_ERROR, "StopTimeSync read serverRet failed!");
        return SOFTBUS_ERR;
    }
    return serverRet;
}
}