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

#include "softbus_server.h"

#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "lnn_bus_center_ipc.h"
#include "securec.h"
#include "softbus_conn_interface.h"
#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server_data.h"
#include "softbus_server_death_recipient.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"
#include "trans_channel_manager.h"
#include "trans_session_service.h"

namespace OHOS {
REGISTER_SYSTEM_ABILITY_BY_ID(SoftBusServer, SOFTBUS_SERVER_SA_ID, true);

static ConnectType ConvertConnectType(ConnectionAddrType type)
{
    switch (type) {
        case CONNECTION_ADDR_BR:
            return CONNECT_BR;
        case CONNECTION_ADDR_BLE:
            return CONNECT_BLE;
        case CONNECTION_ADDR_ETH:
            return CONNECT_TCP;
        case CONNECTION_ADDR_WLAN:
            return CONNECT_TCP;
        default:
            return CONNECT_TYPE_MAX;
    }
}

SoftBusServer::SoftBusServer(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
}

int32_t SoftBusServer::StartDiscovery(const char *pkgName, const SubscribeInfo *info)
{
    int32_t ret = DiscIpcStartDiscovery(pkgName, info);
    return ret;
}

int32_t SoftBusServer::StopDiscovery(const char *pkgName, int subscribeId)
{
    int32_t ret = DiscIpcStopDiscovery(pkgName, subscribeId);
    return ret;
}

int32_t SoftBusServer::PublishService(const char *pkgName, const PublishInfo *info)
{
    int32_t ret = DiscIpcPublishService(pkgName, (PublishInfo *)info);
    return ret;
}

int32_t SoftBusServer::UnPublishService(const char *pkgName, int publishId)
{
    int32_t ret = DiscIpcUnPublishService(pkgName, publishId);
    return ret;
}

int32_t SoftBusServer::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object)
{
    if (clientPkgName == nullptr || object == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "package name or object is nullptr\n");
        return SOFTBUS_ERR;
    }
    if (SoftBusServerData::GetInstance().SoftbusClientIsExist(clientPkgName)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus client is exist.\n");
        return SOFTBUS_OK;
    }
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    if (abilityDeath == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "DeathRecipient object is nullptr\n");
        return SOFTBUS_ERR;
    }
    bool ret = object->AddDeathRecipient(abilityDeath);
    if (!ret) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "AddDeathRecipient failed\n");
        return SOFTBUS_ERR;
    }
    if (SoftBusServerData::GetInstance().SoftbusAddService(clientPkgName, object, abilityDeath) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "softbus add client service failed\n");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "softbus register service success %s\n", clientPkgName);
    return SOFTBUS_OK;
}

int32_t SoftBusServer::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return TransCreateSessionServer(pkgName, sessionName, (int32_t)callingUid, (int32_t)callingPid);
}

int32_t SoftBusServer::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return TransRemoveSessionServer(pkgName, sessionName);
}

int32_t SoftBusServer::OpenSession(const SessionParam* param, TransInfo* info)
{
    return TransOpenSession(param, info);
}

int32_t SoftBusServer::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (sessionName == nullptr || addrInfo == nullptr) {
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectOption connOpt;
    connOpt.type = ConvertConnectType(addrInfo->type);
    switch (connOpt.type) {
        case CONNECT_TCP:
            if (memcpy_s(connOpt.info.ipOption.ip, IP_LEN, addrInfo->info.ip.ip, IP_LEN) != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            connOpt.info.ipOption.port = static_cast<int32_t>(addrInfo->info.ip.port);
            break;
        case CONNECT_BLE:
            if (memcpy_s(connOpt.info.bleOption.bleMac, BT_MAC_LEN, addrInfo->info.ble.bleMac, BT_MAC_LEN) != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            break;
        case CONNECT_BR:
            if (memcpy_s(connOpt.info.brOption.brMac, BT_MAC_LEN, addrInfo->info.br.brMac, BT_MAC_LEN) != EOK) {
                return SOFTBUS_MEM_ERR;
            }
            break;
        default:
            return SOFTBUS_ERR;
    }
    return TransOpenAuthChannel(sessionName, &connOpt);
}

int32_t SoftBusServer::NotifyAuthSuccess(int32_t channelId)
{
    return TransNotifyAuthSuccess(channelId);
}

int32_t SoftBusServer::CloseChannel(int32_t channelId, int32_t channelType)
{
    return TransCloseChannel(channelId, channelType);
}

int32_t SoftBusServer::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    return TransSendMsg(channelId, channelType, data, len, msgType);
}

int32_t SoftBusServer::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    return LnnIpcServerJoin(pkgName, addr, addrTypeLen);
}

int32_t SoftBusServer::LeaveLNN(const char *pkgName, const char *networkId)
{
    return LnnIpcServerLeave(pkgName, networkId);
}

int32_t SoftBusServer::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    return LnnIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
}

int32_t SoftBusServer::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return LnnIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
}

int32_t SoftBusServer::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    return LnnIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
}

int32_t SoftBusServer::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    return LnnIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
}

int32_t SoftBusServer::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    return LnnIpcStopTimeSync(pkgName, targetNetworkId);
}

void SoftBusServer::OnStart()
{
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_INFO, "SoftBusServer OnStart called!\n");
    InitSoftBusServer();
    if (!Publish(this)) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "SoftBusServer publish failed!\n");
    }
}

void SoftBusServer::OnStop() {}
} // namespace OHOS
