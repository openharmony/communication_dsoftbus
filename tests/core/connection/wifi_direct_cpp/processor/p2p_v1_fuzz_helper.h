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

#ifndef P2P_V1_FUZZ_HELPER_H
#define P2P_V1_FUZZ_HELPER_H

#include "data/negotiate_message.h"

#include "fuzz_data_generator.h"

namespace OHOS::SoftBus {

class P2pV1FuzzHelper {
public:
    using FuzzInjector = void (*)(NegotiateMessage &message);
    static int32_t FuzzCommonEnum(int32_t max, int32_t overflow)
    {
        int32_t value = 0;
        GenerateInt32(value);
        return value % (max + overflow);
    }

    static void FuzzCommandType(NegotiateMessage &message)
    {
        auto value = static_cast<LegacyCommandType>(
            FuzzCommonEnum(static_cast<int>(LegacyCommandType::CMD_PC_GET_INTERFACE_INFO_RESP), 3));
        message.SetLegacyP2pCommandType(value);
    }

    static void FuzzContentType(NegotiateMessage &message)
    {
        auto value = static_cast<LegacyContentType>(FuzzCommonEnum(static_cast<int>(LegacyContentType::RESULT), 3));
        message.SetLegacyP2pContentType(value);
    }

    static void FuzzGcChannelList(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pGcChannelList(value);
    }

    static void FuzzGcMac(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pGcMac(value);
    }

    static void FuzzGoMac(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pGoMac(value);
    }

    static void FuzzIP(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pIp(value);
    }

    static void FuzzMac(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pMac(value);
    }

    static void FuzzSelfWifiCfg(NegotiateMessage &message)
    {
        std::string value;
        GenerateString(value);
        message.SetLegacyP2pWifiConfigInfo(value);
    }

    static void FuzzStationFrequency(NegotiateMessage &message)
    {
        int32_t value;
        GenerateInt32(value);
        message.SetLegacyP2pStationFrequency(value);
    }

    static void FuzzVersion(NegotiateMessage &message)
    {
        int32_t value;
        GenerateInt32(value);
        message.SetLegacyP2pVersion(value);
    }

    static void FuzzWideBandSupport(NegotiateMessage &message)
    {
        bool value;
        GenerateBool(value);
        message.SetLegacyP2pWideBandSupported(value);
    }
};

} // namespace OHOS::SoftBus

#endif // P2P_V1_FUZZ_HELPER_H
