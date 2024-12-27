/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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


#include "softbus_client_info_manager.h"

#include "ipc_skeleton.h"
#include "softbus_access_token_adapter.h"
#include "softbus_def.h"
#include "softbus_server.h"

namespace OHOS {
typedef std::pair<std::unordered_multimap<std::string, ClientObjPair>::const_iterator,
    std::unordered_multimap<std::string, ClientObjPair>::const_iterator> ClientObjRange;

SoftbusClientInfoManager &SoftbusClientInfoManager::GetInstance()
{
    static SoftbusClientInfoManager instance;
    return instance;
}

int32_t SoftbusClientInfoManager::SoftbusAddService(const std::string &pkgName, const sptr<IRemoteObject> &object,
    const sptr<IRemoteObject::DeathRecipient> &abilityDeath, int32_t pid)
{
    if (pkgName.empty() || object == nullptr || abilityDeath == nullptr) {
        COMM_LOGE(COMM_SVC, "package name, object or abilityDeath is nullptr\n");
        return SOFTBUS_INVALID_PARAM;
    }
    COMM_LOGI(COMM_SVC, "add SoftbusAddService, pid=%{public}d, pkgname=%{public}s", pid, pkgName.c_str());
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    std::pair<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> clientObject(object, abilityDeath);
    ClientObjPair clientObjPair(pid, clientObject);
    clientObjectMap_.emplace(pkgName, clientObjPair);

    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    std::string permissionName = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    SoftBusRegisterDataSyncPermission(tokenCaller, permissionName.c_str(), pkgName.c_str(), pid);

    return SOFTBUS_OK;
}

int32_t SoftbusClientInfoManager::SoftbusAddServiceInner(const std::string &pkgName, ISessionListener *listener,
    int32_t pid)
{
    if (pkgName.empty() || listener == nullptr) {
        COMM_LOGE(COMM_SVC, "package name or listener is nullptr\n");
        return SOFTBUS_INVALID_PARAM;
    }
    COMM_LOGI(COMM_SVC, "add SoftbusAddServiceInner, pid=%{public}d, pkgname=%{public}s", pid, pkgName.c_str());
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    innerObjectMap_.emplace(pkgName, *listener);

    return SOFTBUS_OK;
}

int32_t SoftbusClientInfoManager::SoftbusRemoveServiceInner(const std::string &pkgName)
{
    if (pkgName.empty()) {
        COMM_LOGE(COMM_SVC, "package name is nullptr\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    innerObjectMap_.erase(pkgName);
    COMM_LOGI(COMM_SVC, "SoftbusRemoveServiceInner, pkgname=%{public}s", pkgName.c_str());

    return SOFTBUS_OK;
}

int32_t SoftbusClientInfoManager::SoftbusRemoveService(const sptr<IRemoteObject> &object, std::string &pkgName,
    int32_t* pid)
{
    if (object == nullptr || pid == nullptr) {
        COMM_LOGE(COMM_SVC, "RemoveService object is nullptr\n");
        return SOFTBUS_INVALID_PARAM;
    }

    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        if (iter->second.second.first == object) {
            pkgName = iter->first;
            *pid = iter->second.first;
            object->RemoveDeathRecipient(iter->second.second.second);
            (void)clientObjectMap_.erase(iter);
            break;
        }
    }
    COMM_LOGI(COMM_SVC, "SoftbusRemoveService, pid=%{public}d, pkgName=%{public}s", (*pid), pkgName.c_str());
    return SOFTBUS_OK;
}

int32_t SoftbusClientInfoManager::GetSoftbusInnerObject(const std::string &pkgName, ISessionListener *listener)
{
    if (listener == nullptr) {
        COMM_LOGE(COMM_SVC, "listener is nullptr\n");
        return SOFTBUS_INVALID_PARAM;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    if (innerObjectMap_.find(pkgName) == innerObjectMap_.end()) {
        COMM_LOGE(COMM_SVC, "no find pkgname=%{public}s in map", pkgName.c_str());
        return SOFTBUS_NOT_FIND;
    }
    *listener = innerObjectMap_[pkgName];
    return SOFTBUS_OK;
}

sptr<IRemoteObject> SoftbusClientInfoManager::GetSoftbusClientProxy(const std::string &pkgName)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    auto iter = clientObjectMap_.find(pkgName);
    if (iter != clientObjectMap_.end()) {
        return iter->second.second.first;
    }
    COMM_LOGE(COMM_SVC, "GetSoftbusClientProxy client proxy is nullptr\n");
    return nullptr;
}

sptr<IRemoteObject> SoftbusClientInfoManager::GetSoftbusClientProxy(const std::string &pkgName, int32_t pid)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    COMM_LOGD(COMM_SVC, "GetSoftbusClientProxy, pid=%{public}d, pkgname=%{public}s", pid, pkgName.c_str());
    ClientObjRange range = clientObjectMap_.equal_range(pkgName);
    auto iter = std::find_if(range.first, range.second, [&pid](auto iter) {return pid == iter.second.first;});
    if (iter != range.second) {
        return iter->second.second.first;
    }
    COMM_LOGE(COMM_SVC, "GetSoftbusClientProxy with pid=%{public}d is nullptr.", pid);
    return nullptr;
}

void SoftbusClientInfoManager::GetSoftbusClientProxyMap(std::multimap<std::string,
    sptr<IRemoteObject>> &softbusClientMap)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        softbusClientMap.emplace(iter->first, iter->second.second.first);
    }
}

bool SoftbusClientInfoManager::SoftbusClientIsExist(const std::string &pkgName, int32_t pid)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    ClientObjRange range = clientObjectMap_.equal_range(pkgName);
    for (auto &iter = range.first; iter != range.second; iter++) {
        if (pid == iter->second.first) {
            return true;
        }
    }
    return false;
}
} // namespace OHOS