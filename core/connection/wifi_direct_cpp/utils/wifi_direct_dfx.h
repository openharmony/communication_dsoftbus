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

#ifndef WIFI_DIRECT_DFX_H
#define WIFI_DIRECT_DFX_H

#include <mutex>
#include <shared_mutex>
#include <functional>
#include <map>
#include "command/connect_command.h"
#include "conn_event.h"
#include "wifi_direct_types.h"
#include "data/negotiate_message.h"

namespace OHOS::SoftBus {
class WifiDirectDfx {
public:
    static WifiDirectDfx &GetInstance()
    {
        static WifiDirectDfx instance;
        return instance;
    }
    void DfxRecord(bool success, int32_t reason, WifiDirectConnectInfo &connectInfo);
    void Record(uint32_t requestId, uint16_t challengeCode);
    void Clear(uint32_t requestId);
    static void SetLinkType(WifiDirectConnectInfo &info);
    void SetReuseFlag(uint32_t requestId);
    bool IsReuse(uint32_t requestId);
    std::string GetChallengeCode(uint32_t requestId);
    static void ReportReceiveAuthLinkMsg(const NegotiateMessage &msg, const std::string &remoteDeviceId);

private:
    void ReportConnEventExtra(ConnEventExtra &extra, WifiDirectConnectInfo &connectInfo);
    
    std::map<uint32_t, uint16_t> challengeCodeMap_;
    std::map<uint32_t, bool> reuseFlagMap_;
    std::recursive_mutex mutex_;
};
} // namespace OHOS::SoftBus

#endif