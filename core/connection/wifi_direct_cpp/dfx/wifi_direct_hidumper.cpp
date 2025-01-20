/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include "wifi_direct_hidumper.h"

#include <nlohmann/json.hpp>
#include <sstream>

#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "entity/p2p_entity.h"
#include "interface_snapshot.h"
#include "legacy/softbus_hidumper_conn.h"
#include "link_snapshot.h"
#include "p2p_entity_snapshot.h"
#include "processor_snapshot.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_scheduler_factory.h"

namespace OHOS::SoftBus {
static constexpr const char *WIFI_DIRECT_HIDUMPER_INFO = "WifiDirectHidumper";
static constexpr int P2P_GROUP_EXIST = 1;
static constexpr int P2P_GROUP_NOT_EXIST = 0;

void WifiDirectHidumper::HidumperInit()
{
    if (hiDumper_ == nullptr) {
        HidumperRegister();
        return;
    }
    hiDumper_();
}

void WifiDirectHidumper::Register(const HiDumper &hidumper)
{
    hiDumper_ = hidumper;
}

void WifiDirectHidumper::HidumperRegister()
{
    SoftBusRegConnVarDump(WIFI_DIRECT_HIDUMPER_INFO, &Dump);
}

void WifiDirectHidumper::DumpInfoHandler(nlohmann::json &json)
{
    nlohmann::json currentTime;
    currentTime["loadTime"] = SoftBusFormatTimestamp(SoftBusGetSysTimeMs());
    json.push_back(currentTime);

    nlohmann::json p2pGroupMsg;
    p2pGroupMsg["p2pGroupExist"] = JudgeP2pGroup();
    json.push_back(p2pGroupMsg);

    P2pEntitySnapshot p2pEntitySnapshot;
    P2pEntity::GetInstance().Dump(p2pEntitySnapshot);
    p2pEntitySnapshot.Marshalling(json);

    std::list<std::shared_ptr<ProcessorSnapshot>> processorSnapshots;
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().Dump(processorSnapshots);
    for (const auto &processor : processorSnapshots) {
        processor->Marshalling(json);
    }

    std::list<std::shared_ptr<LinkSnapshot>> linkSnapshots;
    LinkManager::GetInstance().Dump(linkSnapshots);
    for (const auto &link : linkSnapshots) {
        link->Marshalling(json);
    }

    std::list<std::shared_ptr<InterfaceSnapshot>> interfaceSnapshots;
    InterfaceManager::GetInstance().Dump(interfaceSnapshots);
    for (const auto &interface : interfaceSnapshots) {
        interface->Marshalling(json);
    }
}

int WifiDirectHidumper::JudgeP2pGroup()
{
    auto groupInfo = std::make_shared<WifiP2pGroupInfo>();
    auto ret = GetCurrentGroup(groupInfo.get());
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == WIFI_SUCCESS, ret, CONN_WIFI_DIRECT, "get current group failed, error=%{public}d", ret);
    return (groupInfo->frequency != 0) ? P2P_GROUP_EXIST : P2P_GROUP_NOT_EXIST;
}
} // namespace OHOS::SoftBus

int Dump(int fd)
{
    nlohmann::json json;
    OHOS::SoftBus::WifiDirectHidumper::DumpInfoHandler(json);

    SOFTBUS_DPRINTF(fd, "%s\n", json.dump().c_str());
    return SOFTBUS_OK;
}