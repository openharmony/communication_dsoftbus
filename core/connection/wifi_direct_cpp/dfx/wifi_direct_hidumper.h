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

#ifndef WIFI_DIRECT_HIDUMP_H
#define WIFI_DIRECT_HIDUMP_H

#include <functional>
#include <list>
#include <memory>
#include <nlohmann/json.hpp>
#include <string>

namespace OHOS::SoftBus {
class WifiDirectHidumper {
public:
    static WifiDirectHidumper &GetInstance()
    {
        static WifiDirectHidumper instance;
        return instance;
    }

    void HidumperInit();
    using HiDumper = std::function<int()>;
    void Register(const HiDumper &hidumper);
    static void HidumperRegister();
    static void DumpInfoHandler(nlohmann::json &json);
    static int JudgeP2pGroup();

private:
    static inline HiDumper hiDumper_;
};
} // namespace OHOS::SoftBus

#ifdef __cplusplus
extern "C" {
#endif

int Dump(int fd);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif