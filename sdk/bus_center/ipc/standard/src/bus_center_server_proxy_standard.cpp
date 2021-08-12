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
#include "message_parcel.h"
#include "softbus_adapter_mem.h"
#include "softbus_errcode.h"
#include "softbus_ipc_def.h"
#include "softbus_log.h"
#include "ipc_skeleton.h"
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
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
        LOG_ERR("Get GetSystemAbility failed!\n");
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

int32_t BusCenterServerProxy::OpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
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
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    if (!data.WriteCString(pkgName)) {
        LOG_ERR("JoinLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(addrTypeLen)) {
        LOG_ERR("JoinLNN write addr type length failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteRawData(addr, addrTypeLen)) {
        LOG_ERR("JoinLNN write addr failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_JOIN_LNN, data, reply, option) != 0) {
        LOG_ERR("JoinLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    if (!reply.ReadInt32(serverRet)) {
        LOG_ERR("JoinLNN read serverRet failed!");
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
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("LeaveLNN write client name failed!");
        return SOFTBUS_ERR;
    }
    ret = data.WriteCString(networkId);
    if (!ret) {
        LOG_ERR("LeaveLNN write networkId failed!");
        return SOFTBUS_ERR;
    }

    MessageParcel reply;
    MessageOption option;
    int32_t err = remote->SendRequest(SERVER_LEAVE_LNN, data, reply, option);
    if (err != 0) {
        LOG_ERR("LeaveLNN send request failed!");
        return SOFTBUS_ERR;
    }
    int32_t serverRet = 0;
    ret = reply.ReadInt32(serverRet);
    if (!ret) {
        LOG_ERR("LeaveLNN read serverRet failed!");
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
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetAllOnlineNodeInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("GetAllOnlineNodeInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_ALL_ONLINE_NODE_INFO, data, reply, option) != 0) {
        LOG_ERR("GetAllOnlineNodeInfo send request failed!");
        return SOFTBUS_ERR;
    }
    if (!reply.ReadInt32(*infoNum)) {
        LOG_ERR("GetAllOnlineNodeInfo read infoNum failed!");
        return SOFTBUS_ERR;
    }
    int32_t infoSize = (*infoNum) * (int32_t)infoTypeLen;
    *info = nullptr;
    if (infoSize > 0) {
        void *nodeInfo = (void *)reply.ReadRawData(infoSize);
        if (nodeInfo == nullptr) {
            LOG_ERR("GetAllOnlineNodeInfo read node info failed!");
            return SOFTBUS_ERR;
        }
        *info = SoftBusMalloc(infoSize);
        if (*info == nullptr) {
            LOG_ERR("GetAllOnlineNodeInfo malloc failed!");
            return SOFTBUS_ERR;
        }
        if (memcpy_s(*info, infoSize, nodeInfo, infoSize) != EOK) {
            LOG_ERR("GetAllOnlineNodeInfo copy node info failed!");
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
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetLocalDeviceInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteUint32(infoTypeLen)) {
        LOG_ERR("GetLocalDeviceInfo write info type length failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_LOCAL_DEVICE_INFO, data, reply, option) != 0) {
        LOG_ERR("GetLocalDeviceInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *nodeInfo = (void *)reply.ReadRawData(infoTypeLen);
    if (nodeInfo == nullptr) {
        LOG_ERR("GetLocalDeviceInfo read node info failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(info, infoTypeLen, nodeInfo, infoTypeLen) != EOK) {
        LOG_ERR("GetLocalDeviceInfo copy node info failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t BusCenterServerProxy::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    if (networkId == nullptr || buf == nullptr) {
        LOG_ERR("params are nullptr!");
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remote = GetSystemAbility();
    if (remote == nullptr) {
        LOG_ERR("remote is nullptr!");
        return SOFTBUS_ERR;
    }

    MessageParcel data;
    int32_t ret = data.WriteCString(pkgName);
    if (!ret) {
        LOG_ERR("GetNodeKeyInfo write client name failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteCString(networkId)) {
        LOG_ERR("GetNodeKeyInfo write networkId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(key)) {
        LOG_ERR("GetNodeKeyInfo write key failed!");
        return SOFTBUS_ERR;
    }
    if (!data.WriteInt32(len)) {
        LOG_ERR("GetNodeKeyInfo write buf len failed!");
        return SOFTBUS_ERR;
    }
    MessageParcel reply;
    MessageOption option;
    if (remote->SendRequest(SERVER_GET_NODE_KEY_INFO, data, reply, option) != 0) {
        LOG_ERR("GetNodeKeyInfo send request failed!");
        return SOFTBUS_ERR;
    }
    void *retBuf = (void *)reply.ReadRawData(len);
    if (retBuf == nullptr) {
        LOG_ERR("GetNodeKeyInfo read retBuf failed!");
        return SOFTBUS_ERR;
    }
    if (memcpy_s(buf, len, retBuf, len) != EOK) {
        LOG_ERR("GetNodeKeyInfo copy node key info failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
}