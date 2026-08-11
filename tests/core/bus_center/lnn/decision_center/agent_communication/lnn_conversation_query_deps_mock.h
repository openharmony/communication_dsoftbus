/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#ifndef LNN_CONVERSATION_QUERY_DEPS_MOCK_H
#define LNN_CONVERSATION_QUERY_DEPS_MOCK_H

#include <gmock/gmock.h>

#include "bus_center_manager.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_feature_capability.h"
#include "lnn_local_net_ledger.h"
#include "lnn_ohos_account.h"
#include "lnn_ohos_account_adapter.h"

namespace OHOS {
class LnnConvQueryDepsInterface {
public:
    LnnConvQueryDepsInterface() = default;
    virtual ~LnnConvQueryDepsInterface() = default;

    virtual int32_t LnnGetLocalNodeInfoSafe(NodeInfo *info) = 0;
    virtual int32_t LnnGetRemoteNodeInfoById(const char *id, IdCategory type, NodeInfo *info) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByNetworkIdPacked(const char *networkId, NodeInfo *info) = 0;
    virtual int32_t LnnRetrieveDeviceInfoByUdidPacked(const char *udid, NodeInfo *deviceInfo) = 0;
    virtual bool IsFeatureSupport(uint64_t feature, FeatureCapability capaBit) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t JudgeDeviceTypeAndGetOsAccountIds(void) = 0;
    virtual int32_t LnnGetLocalNum64Info(InfoKey key, int64_t *info) = 0;
    virtual bool LnnIsDefaultOhosAccount(void) = 0;
};

class LnnConvQueryDepsInterfaceMock : public LnnConvQueryDepsInterface {
public:
    LnnConvQueryDepsInterfaceMock();
    ~LnnConvQueryDepsInterfaceMock() override;

    MOCK_METHOD1(LnnGetLocalNodeInfoSafe, int32_t (NodeInfo *));
    MOCK_METHOD3(LnnGetRemoteNodeInfoById, int32_t (const char *, IdCategory, NodeInfo *));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByNetworkIdPacked, int32_t (const char *, NodeInfo *));
    MOCK_METHOD2(LnnRetrieveDeviceInfoByUdidPacked, int32_t (const char *, NodeInfo *));
    MOCK_METHOD2(IsFeatureSupport, bool (uint64_t, FeatureCapability));
    MOCK_METHOD2(LnnGetOnlineStateById, bool (const char *, IdCategory));
    MOCK_METHOD0(JudgeDeviceTypeAndGetOsAccountIds, int32_t (void));
    MOCK_METHOD2(LnnGetLocalNum64Info, int32_t (InfoKey, int64_t *));
    MOCK_METHOD0(LnnIsDefaultOhosAccount, bool (void));
};
} // namespace OHOS

#endif // LNN_CONVERSATION_QUERY_DEPS_MOCK_H
