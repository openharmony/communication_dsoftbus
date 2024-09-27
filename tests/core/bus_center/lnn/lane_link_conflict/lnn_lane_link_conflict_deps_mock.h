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

#ifndef LNN_LANE_LINK_CONFLICT_DEPS_MOCK_H
#define LNN_LANE_LINK_CONFLICT_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_info_key.h"
#include "softbus_error_code.h"

constexpr char PEER_UDID_HASH_STR[] = "444455556666abcd";

namespace OHOS {
class LaneLinkConflictDepsInterface {
public:
    LaneLinkConflictDepsInterface() {};
    virtual ~LaneLinkConflictDepsInterface() {};
    virtual int32_t InitLinkWifiDirect(void) = 0;
    virtual void DeInitLinkWifiDirect(void) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
    virtual int32_t SoftBusGenerateStrHash(const unsigned char *str, uint32_t len, unsigned char *hash) = 0;
    virtual int32_t ConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen);
};

class LaneLinkConflictDepsInterfaceMock : public LaneLinkConflictDepsInterface {
public:
    LaneLinkConflictDepsInterfaceMock();
    ~LaneLinkConflictDepsInterfaceMock() override;
    MOCK_METHOD0(InitLinkWifiDirect, int32_t (void));
    MOCK_METHOD0(DeInitLinkWifiDirect, void (void));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char*, InfoKey, char*, uint32_t));
    MOCK_METHOD3(SoftBusGenerateStrHash, int32_t (const unsigned char *, uint32_t, unsigned char *));
    MOCK_METHOD4(ConvertBytesToHexString, int32_t (char *, uint32_t, const unsigned char *, uint32_t));
    static int32_t ActionOfConvertBytesToHexString(char *outBuf, uint32_t outBufLen,
        const unsigned char *inBuf, uint32_t inLen);
};
} // namespace OHOS
#endif // LNN_LANE_LINK_CONFLICT_DEPS_MOCK_H
