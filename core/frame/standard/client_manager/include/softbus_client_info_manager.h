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

#ifndef SOFTBUS_CLIENT_INFO_MANAGER_H
#define SOFTBUS_CLIENT_INFO_MANAGER_H

#include <map>
#include <mutex>
#include <list>
#include <unordered_map>
#include "iremote_broker.h"
#include "iremote_object.h"
#include "iremote_proxy.h"
#include "session.h"

namespace OHOS {
typedef std::pair<int32_t, std::pair<sptr<IRemoteObject>, sptr<IRemoteObject::DeathRecipient>>> ClientObjPair;
class SoftbusClientInfoManager {
public:
    static SoftbusClientInfoManager &GetInstance();
    int32_t SoftbusAddService(const std::string &pkgName, const sptr<IRemoteObject> &object,
        const sptr<IRemoteObject::DeathRecipient> &abilityDeath, int32_t pid);
    int32_t SoftbusRemoveService(const sptr<IRemoteObject> &object, std::string &pkgName, int32_t* pid);
    int32_t SoftbusAddServiceInner(const std::string &pkgName, ISessionListener *listener, int32_t pid);
    int32_t SoftbusRemoveServiceInner(const std::string &pkgName);
    int32_t GetSoftbusInnerObject(const std::string &pkgName, ISessionListener *listener);
    sptr<IRemoteObject> GetSoftbusClientProxy(const std::string &pkgName);
    sptr<IRemoteObject> GetSoftbusClientProxy(const std::string &pkgName, int32_t pid);
    void GetSoftbusClientProxyMap(std::multimap<std::string, sptr<IRemoteObject>> &softbusClientMap);
    bool SoftbusClientIsExist(const std::string &pkgName, int32_t pid);

private:
    ~SoftbusClientInfoManager() = default;
    SoftbusClientInfoManager() = default;
    std::recursive_mutex clientObjectMapLock_;
    std::unordered_multimap<std::string, ClientObjPair> clientObjectMap_;
    std::map<std::string, ISessionListener> innerObjectMap_;
    DISALLOW_COPY_AND_MOVE(SoftbusClientInfoManager);
};
} // namespace OHOS
#endif