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

#include "softbus_client_info_manager.h"
#include "permission_status_change_cb.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_server.h"

namespace OHOS {
typedef std::pair<std::unordered_multimap<std::string, ClientObjPair>::iterator,
    std::unordered_multimap<std::string, ClientObjPair>::iterator> ClientObjRange;

NO_SANITIZE("cfi") SoftbusClientInfoManager &SoftbusClientInfoManager::GetInstance()
{
    static SoftbusClientInfoManager instance;
    return instance;
}

int32_t SoftbusClientInfoManager::SoftbusAddService(const std::string &pkgName, const sptr<IRemoteObject> &object,
    const sptr<IRemoteObject::DeathRecipient> &abilityDeath, int32_t pid)
{
    if (pkgName.empty() || object == nullptr || abilityDeath == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "package name, object or abilityDeath is nullptr\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    std::pair<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> clientObject(object, abilityDeath);
    ClientObjPair clientObjPair(pid, clientObject);
    clientObjectMap_.emplace(pkgName, clientObjPair);

    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    std::string permissionName = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    RegisterDataSyncPermission(tokenCaller, permissionName, pkgName, pid);

    return SOFTBUS_OK;
}

int32_t SoftbusClientInfoManager::SoftbusRemoveService(const sptr<IRemoteObject> &object, std::string &pkgName,
    int32_t* pid)
{
    if (object == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveService object is nullptr\n");
        return SOFTBUS_ERR;
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
    return SOFTBUS_OK;
}

sptr<IRemoteObject> SoftbusClientInfoManager::GetSoftbusClientProxy(const std::string &pkgName)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    auto iter = clientObjectMap_.find(pkgName);
    if (iter != clientObjectMap_.end()) {
        return iter->second.second.first;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetSoftbusClientProxy client proxy is nullptr\n");
    return nullptr;
}

sptr<IRemoteObject> SoftbusClientInfoManager::GetSoftbusClientProxy(const std::string &pkgName, int32_t pid)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    ClientObjRange range = clientObjectMap_.equal_range(pkgName);
    for (auto iter = range.first; iter != range.second; iter++) {
        if (pid == iter->second.first) {
            return iter->second.second.first;
        }
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetSoftbusClientProxy with pid is nullptr\n");
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
    for (auto iter = range.first; iter != range.second; iter++) {
        if (pid == iter->second.first) {
            return true;
        }
    }
    return false;
}
} // namespace OHOS