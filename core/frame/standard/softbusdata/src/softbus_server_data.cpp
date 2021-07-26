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

#include "softbus_server_data.h"

#include "softbus_errcode.h"
#include "softbus_log.h"

namespace OHOS {
SoftBusServerData &SoftBusServerData::GetInstance()
{
    static SoftBusServerData instance;
    return instance;
}

int32_t SoftBusServerData::SoftbusAddService(const std::string &pkgName, const sptr<IRemoteObject> &object,
    const sptr<IRemoteObject::DeathRecipient> &abilityDeath)
{
    if (pkgName.empty() || object == nullptr || abilityDeath == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "package name, object or abilityDeath is nullptr\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    std::pair<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>> clientObject(object, abilityDeath);
    clientObjectMap_.emplace(pkgName, clientObject);
    return SOFTBUS_OK;
}

int32_t SoftBusServerData::SoftbusRemoveService(const sptr<IRemoteObject> &object, std::string &pkgName)
{
    if (object == nullptr) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "RemoveService object is nullptr\n");
        return SOFTBUS_ERR;
    }
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        if (iter->second.first == object) {
            pkgName = iter->first;
            object->RemoveDeathRecipient(iter->second.second);
            (void)clientObjectMap_.erase(iter);
            break;
        }
    }
    return SOFTBUS_OK;
}

sptr<IRemoteObject> SoftBusServerData::GetSoftbusClientProxy(const std::string &pkgName)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    auto iter = clientObjectMap_.find(pkgName);
    if (iter != clientObjectMap_.end()) {
        return iter->second.first;
    }
    SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "GetSoftbusClientProxy client proxy is nullptr\n");
    return nullptr;
}

void SoftBusServerData::GetSoftbusClientProxyMap(std::map<std::string, sptr<IRemoteObject>> &softbusClientMap)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    for (auto iter = clientObjectMap_.begin(); iter != clientObjectMap_.end(); ++iter) {
        softbusClientMap.emplace(iter->first, iter->second.first);
    }
}

bool SoftBusServerData::SoftbusClientIsExist(const std::string &pkgName)
{
    std::lock_guard<std::recursive_mutex> autoLock(clientObjectMapLock_);
    auto iter = clientObjectMap_.find(pkgName);
    if (iter != clientObjectMap_.end()) {
        return true;
    }
    return false;
}
} // namespace OHOS