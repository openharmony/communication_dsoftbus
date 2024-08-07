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

#ifndef WIFI_DIRECT_IP_MANAGER_H
#define WIFI_DIRECT_IP_MANAGER_H

#include <bitset>
#include <map>
#include <mutex>
#include <set>
#include <string>
#include <vector>

#include "conn_log.h"
#include "data/ipv4_info.h"
#include "wifi_direct_initiator.h"

namespace OHOS::SoftBus {
class WifiDirectIpManager {
public:
    static WifiDirectIpManager& GetInstance()
    {
        static WifiDirectIpManager instance;
        {
            std::lock_guard lock(clearMutex_);
            if (!hasClear_) {
                ClearAllIpv4();
                hasClear_ = true;
            }
        }
        return instance;
    }
    static void Init();

    std::string ApplyIpv6(const std::string &mac);
    int32_t ApplyIpv4(const std::vector<Ipv4Info> &localArray, const std::vector<Ipv4Info> &remoteArray,
                      Ipv4Info &source, Ipv4Info &sink);
    int32_t ConfigIpv6(const std::string &interface, const std::string &ip);
    int32_t ConfigIpv4(
        const std::string &interface, const Ipv4Info &local, const Ipv4Info &remote, const std::string &remoteMac);
    void ReleaseIpv4(
        const std::string &interface, const Ipv4Info &local, const Ipv4Info &remote, const std::string &remoteMac);
    static void ClearAllIpv4();

    void Lock()
    {
        CONN_LOGD(CONN_WIFI_DIRECT, "lock");
        mutex_.lock();
    }
    void Unlock()
    {
        CONN_LOGD(CONN_WIFI_DIRECT, "unlock");
        mutex_.unlock();
    }

    static constexpr int32_t EUI_64_IDENTIFIER_LEN = 64;
    static constexpr int32_t LOCAL_NETWORK_ID = 99;

    static std::string ApplySubNet(const std::vector<Ipv4Info> &localArray, const std::vector<Ipv4Info> &remoteArray);

    static int32_t GetNetworkGateWay(const std::string &ipString, std::string &gateWay);
    static int32_t GetNetworkDestination(const std::string &ipString, std::string &destination);

    static int32_t AddInterfaceAddress(const std::string &interface, const std::string &ipString, int32_t prefixLength);
    static int32_t DeleteInterfaceAddress(
        const std::string &interface, const std::string &ipString, int32_t prefixLength);
    static int32_t AddStaticArp(
        const std::string &interface, const std::string &ipString, const std::string &macString);
    static int32_t DeleteStaticArp(
        const std::string &interface, const std::string &ipString, const std::string &macString);

private:
    class Initiator {
    public:
        Initiator()
        {
            WifiDirectInitiator::GetInstance().Add(WifiDirectIpManager::Init);
        }
    };

    std::recursive_mutex mutex_;
    static inline Initiator initiator_;

    static inline bool hasClear_ = false;
    static inline std::recursive_mutex clearMutex_;
};
} // namespace OHOS::SoftBus
#endif /* WIFI_DIRECT_IP_MANAGER_H */
