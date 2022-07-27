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

#ifndef DEVICE_MANAGER_H
#define DEVICE_MANAGER_H

#include <string>
#include <vector>

class DeviceManager {
public:
    ~DeviceManager() {};

    std::string GetRemoteByIndex(uint32_t index);
    void WaitNetworkSizeMoreThan(uint32_t count);

    static DeviceManager *Instance();

private:
    DeviceManager() {};
    std::string m_localNetworkId;
    std::vector<std::string> m_remoteList;
    static DeviceManager *m_instance;
};
#endif
