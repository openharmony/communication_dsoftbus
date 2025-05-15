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

#ifndef LNN_SELECT_RULE_MOCK_H
#define LNN_SELECT_RULE_MOCK_H

#include <gmock/gmock.h>

#include "lnn_distributed_net_ledger.h"
#include "lnn_node_info.h"

namespace OHOS {
class LnnSelectRuleInterface {
public:
    LnnSelectRuleInterface() {};
    virtual ~LnnSelectRuleInterface() {};

    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteNumU32Info(const char *networkId, InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnGetRemoteStrInfo(const char *netWorkId, InfoKey key, char *info, uint32_t len) = 0;
};

class LnnSelectRuleInterfaceMock : public LnnSelectRuleInterface {
public:
    LnnSelectRuleInterfaceMock();
    ~LnnSelectRuleInterfaceMock() override;

    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey, uint32_t *));
    MOCK_METHOD3(LnnGetRemoteNumU32Info, int32_t (const char *, InfoKey, uint32_t *));
    MOCK_METHOD4(LnnGetRemoteStrInfo, int32_t (const char*, InfoKey, char*, uint32_t));
};
} // namespace OHOS
#endif // LNN_SELECT_RULE_MOCK_H
