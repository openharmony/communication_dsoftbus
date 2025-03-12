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

#ifndef HB_HEARTBEAT_UTILS_MOCK_H
#define HB_HEARTBEAT_UTILS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_info_key.h"
#include "lnn_feature_capability.h"
#include "wifi_direct_manager.h"

namespace OHOS {
class HbHeartbeatUtilsInterface {
public:
    HbHeartbeatUtilsInterface() {};
    virtual ~HbHeartbeatUtilsInterface() {};
    virtual int32_t ConvertBtMacToStrNoColon(char *strMac, uint32_t strMacLen, const uint8_t *binMac,
        uint32_t binMacLen) = 0;
    virtual int32_t StringToUpperCase(const char *str, char *buf, int32_t size) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen, const unsigned char *inBuf,
        uint32_t inLen) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual struct WifiDirectManager *GetWifiDirectManager(void) = 0;
};
class HbHeartbeatUtilsInterfaceMock : public HbHeartbeatUtilsInterface {
public:
    HbHeartbeatUtilsInterfaceMock();
    ~HbHeartbeatUtilsInterfaceMock() override;
    MOCK_METHOD4(ConvertBtMacToStrNoColon, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD3(StringToUpperCase, int32_t(const char *, char *, int32_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t(const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t(char *, uint32_t, const unsigned char *, uint32_t));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t(const char *, InfoKey, uint32_t *));
    MOCK_METHOD0(GetWifiDirectManager, WifiDirectManager *());
};
} // namespace OHOS
#endif // HB_HEARTBEAT_UTILS_MOCK_H
