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

#include "softbus_disc_server.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server_frame.h"
#include "system_ability_definition.h"

extern "C" int __attribute__ ((weak)) DiscIpcPublishService(const char *packageName, const PublishInfo *info)
{
    LOG_INFO("DiscIpcPublishService Weak!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) DiscIpcUnPublishService(const char *packageName, int publishId)
{
    LOG_INFO("DiscIpcUnPublishService Weak!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) DiscIpcStartDiscovery(const char *packageName, const SubscribeInfo *info)
{
    LOG_INFO("DiscIpcStartDiscovery Weak!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) DiscIpcStopDiscovery(const char *packageName, int subscribeId)
{
    LOG_INFO("DiscIpcStopDiscovery Weak!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) TransCreateSessionServer(const char *pkgName, const char *sessionName)
{
    LOG_INFO("TransCreateSessionServer!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) TransRemoveSessionServer(const char *pkgName, const char *sessionName)
{
    LOG_INFO("TransRemoveSessionServer!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) TransOpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    LOG_INFO("TransOpenSession!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) TransCloseChannel(int32_t channelId)
{
    LOG_INFO("TransCloseChannel!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) TransSendMsg(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    LOG_INFO("TransCloseChannel!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) LnnIpcServerJoin(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    LOG_INFO("LnnIpcServerJoin weak!\n");
    return SOFTBUS_OK;
}

extern "C" int __attribute__ ((weak)) LnnIpcServerLeave(const char *pkgName, const char *networkId)
{
    LOG_INFO("LnnIpcServerLeave weak!\n");
    return SOFTBUS_NOT_IMPLEMENT;
}

extern "C" int __attribute__ ((weak)) LnnIpcGetAllOnlineNodeInfo(const char *pkgName, void **info,
    uint32_t infoTypeLen, int *infoNum)
{
    LOG_INFO("LnnIpcGetAllOnlineNodeInfo weak!\n");
    return SOFTBUS_NOT_IMPLEMENT;
}

extern "C" int __attribute__ ((weak)) LnnIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    LOG_INFO("LnnIpcGetLocalDeviceInfo weak!\n");
    return SOFTBUS_NOT_IMPLEMENT;
}

extern "C" int __attribute__ ((weak)) GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    LOG_INFO("LnnIpcGetLocalDeviceInfo weak!\n");
    return SOFTBUS_NOT_IMPLEMENT;
}

extern "C" int __attribute__ ((weak)) LnnIpcGetNodeKeyInfo(const char *pkgName, const char *networkId,
    int key, unsigned char *buf, uint32_t len)
{
    LOG_INFO("LnnIpcGetNodeKeyInfo weak!\n");
    return SOFTBUS_NOT_IMPLEMENT;
}

namespace OHOS {
REGISTER_SYSTEM_ABILITY_BY_ID(SoftBusServer, SOFTBUS_SERVER_SA_ID, true);
std::mutex SoftBusServer::instanceLock_;
sptr<SoftBusServer> SoftBusServer::instance_;
std::map<std::string, sptr<IRemoteObject>> SoftBusServer::clientObjectMap_;

SoftBusServer::SoftBusServer(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
}

sptr<SoftBusServer> SoftBusServer::GetInstance()
{
    if (instance_ == nullptr) {
        std::lock_guard<std::mutex> autoLock(instanceLock_);
        if (instance_ == nullptr) {
            instance_ = new (std::nothrow) SoftBusServer(SOFTBUS_SERVER_SA_ID, true);
        }
    }
    return instance_;
}

int32_t SoftBusServer::StartDiscovery(const char *pkgName, const void *info)
{
    int32_t ret = DiscIpcStartDiscovery(pkgName, (SubscribeInfo *)info);
    return ret;
}

int32_t SoftBusServer::StopDiscovery(const char *pkgName, int subscribeId)
{
    int32_t ret = DiscIpcStopDiscovery(pkgName, subscribeId);
    return ret;
}

int32_t SoftBusServer::PublishService(const char *pkgName, const void *info)
{
    int32_t ret = DiscIpcPublishService(pkgName, (PublishInfo *)info);
    return ret;
}

int32_t SoftBusServer::UnPublishService(const char *pkgName, int publishId)
{
    int32_t ret = DiscIpcUnPublishService(pkgName, publishId);
    return ret;
}

sptr<ISoftBusClient> SoftBusServer::GetSoftbusClientProxy(const char *pkgName)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    auto iter = clientObjectMap_.find(pkgName);
    if (iter != clientObjectMap_.end()) {
        sptr<ISoftBusClient> clientProxy = iface_cast<ISoftBusClient>(iter->second);
        if (clientProxy != nullptr) {
            return clientProxy;
        }
    }
    LOG_ERR("GetSoftbusClientProxy client proxy is nullptr\n");
    return nullptr;
}

void SoftBusServer::GetSoftbusClientProxyMap(std::map<std::string, sptr<ISoftBusClient>> &softbusClientMap)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        sptr<ISoftBusClient> clientProxy = iface_cast<ISoftBusClient>(iter->second);
        softbusClientMap.insert(std::pair<std::string, sptr<ISoftBusClient>>(iter->first, clientProxy));
    }
}

int32_t SoftBusServer::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object)
{
    if (object == nullptr) {
        LOG_ERR("RegisterService object is nullptr\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    clientObjectMap_.insert(std::pair<std::string, sptr<IRemoteObject>>(clientPkgName, object));

    abilityDeath_ = sptr<IRemoteObject::DeathRecipient>(new (std::nothrow) SoftBusDeathRecipient());
    if (abilityDeath_ == nullptr) {
        LOG_ERR("DeathRecipient object is nullptr\n");
        return SOFTBUS_ERR;
    }
    bool ret = object->AddDeathRecipient(abilityDeath_);
    if (!ret) {
        LOG_ERR("AddDeathRecipient failed\n");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServer::SoftbusRemoveService(const sptr<IRemoteObject> &object)
{
    if (object == nullptr) {
        LOG_ERR("RemoveService object is nullptr\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        if (iter->second == object) {
            (void)clientObjectMap_.erase(iter);
            if (abilityDeath_ != nullptr) {
                object->RemoveDeathRecipient(abilityDeath_);
            }
            LOG_INFO("softbus client removed, size : %u", clientObjectMap_.size());
            break;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServer::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    return TransCreateSessionServer(pkgName, sessionName);
}

int32_t SoftBusServer::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return TransRemoveSessionServer(pkgName, sessionName);
}

int32_t SoftBusServer::OpenSession(const char *mySessionName, const char *peerSessionName,
    const char *peerDeviceId, const char *groupId, int32_t flags)
{
    return TransOpenSession(mySessionName, peerSessionName, peerDeviceId, groupId, flags);
}

int32_t SoftBusServer::CloseChannel(int32_t channelId)
{
    return TransCloseChannel(channelId);
}

int32_t SoftBusServer::SendMessage(int32_t channelId, const void *data, uint32_t len, int32_t msgType)
{
    return TransSendMsg(channelId, data, len, msgType);
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

void SoftBusServer::OnStart()
{
    LOG_INFO("SoftBusServer OnStart called!\n");
    if (!Publish(this)) {
        LOG_ERR("SoftBusServer publish failed!\n");
    }
    InitSoftBusServer();
}

void SoftBusServer::OnStop()
{
    if (!clientObjectMap_.empty()) {
        std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
        clientObjectMap_.clear();
    }
}
} // namespace OHOS
