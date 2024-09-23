/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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
#include "device_manager.h"

#include <algorithm>
#include <unistd.h>

#include "bus_center/softbus_bus_center.h"
#include "test_suite.h"

DeviceManager* DeviceManager::m_instance = nullptr;

DeviceManager *DeviceManager::Instance()
{
    if (m_instance == nullptr) {
        m_instance = new DeviceManager();
    }
    return m_instance;
}

std::string DeviceManager::GetRemoteByIndex(uint32_t index)
{
    if (index >= m_remoteList.size()) {
        return "NoSuchDevice";
    }
    return m_remoteList[index];
}

void DeviceManager::WaitNetworkSizeMoreThan(uint32_t count)
{
    NodeBasicInfo *nodeInfo = nullptr;
    int32_t infoNum = 0;
    do {
        int32_t ret = GetAllNodeDeviceInfo(ECHO_SERVICE_PKGNAME, &nodeInfo, &infoNum);
        if (ret == 0) {
            if (infoNum >= count) {
                break;
            }
            LOG("device count=%d", infoNum);
            for (uint32_t i = 0; i < infoNum; i++) {
                LOG("%s:networkId=%s", __func__, nodeInfo[i].networkId);
            }
        }

        FreeNodeInfo(nodeInfo);
        nodeInfo = nullptr;
        sleep(3L);
    } while (infoNum < count);

    NodeBasicInfo localNode;

    GetLocalNodeDeviceInfo(ECHO_SERVICE_PKGNAME, &localNode);
    m_localNetworkId = localNode.networkId;

    m_remoteList.clear();
    if (nodeInfo != nullptr) {
        for (uint32_t i = 0; i < infoNum; i++) {
            if (m_localNetworkId != nodeInfo[i].networkId) {
                m_remoteList.push_back(nodeInfo[i].networkId);
            }
        }
    }
    std::sort(m_remoteList.begin(), m_remoteList.end());
    FreeNodeInfo(nodeInfo);
}
