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

#ifndef LNN_NET_LEDGER_TEST_MOCK_H
#define LNN_NET_LEDGER_TEST_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_info_key_struct.h"
#include "lnn_feature_capability_struct.h"

namespace OHOS {
class LnnNetLedgerInterface {
public:
    LnnNetLedgerInterface() {};
    virtual ~LnnNetLedgerInterface() {};

    virtual int32_t LnnGetLocalNumU64Info(InfoKey key, uint64_t *info) = 0;
    virtual int32_t LnnSetLocalNum64Info(InfoKey key, int64_t info) = 0;
    virtual bool IsSupportLpFeaturePacked(void) = 0;
    virtual bool LnnIsSupportLpSparkFeaturePacked(void) = 0;
    virtual bool LnnIsFeatureSupportDetailPacked(void) = 0;
    virtual int32_t LnnClearFeatureCapability(uint64_t *feature, FeatureCapability capaBit) = 0;
    virtual int32_t LnnSetFeatureCapability(uint64_t *feature, FeatureCapability capaBit) = 0;
    virtual int32_t LnnSetLocalByteInfo(InfoKey key, const uint8_t *info, uint32_t len) = 0;
};
class LnnNetLedgerInterfaceMock : public LnnNetLedgerInterface {
public:
    LnnNetLedgerInterfaceMock();
    ~LnnNetLedgerInterfaceMock() override;
    MOCK_METHOD2(LnnGetLocalNumU64Info, int32_t(InfoKey, uint64_t *));
    MOCK_METHOD2(LnnSetLocalNum64Info, int32_t(InfoKey, int64_t));
    MOCK_METHOD0(IsSupportLpFeaturePacked, bool(void));
    MOCK_METHOD0(LnnIsSupportLpSparkFeaturePacked, bool(void));
    MOCK_METHOD0(LnnIsFeatureSupportDetailPacked, bool(void));
    MOCK_METHOD2(LnnClearFeatureCapability, int32_t(uint64_t *, FeatureCapability));
    MOCK_METHOD2(LnnSetFeatureCapability, int32_t(uint64_t *, FeatureCapability));
    MOCK_METHOD3(LnnSetLocalByteInfo, int32_t(InfoKey, const uint8_t *, uint32_t));
};
} // namespace OHOS
#endif // LNN_NET_LEDGER_TEST_MOCK_H