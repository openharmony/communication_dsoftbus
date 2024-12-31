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

#ifndef LNN_NET_LEDGER_COMMON_MOCK_H
#define LNN_NET_LEDGER_COMMON_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_local_net_ledger.h"
namespace OHOS {
class NetLedgerCommonInterface {
public:
    NetLedgerCommonInterface() {};
    virtual ~NetLedgerCommonInterface() {};

    virtual int32_t LnnSetLocalNumU16Info(InfoKey key, uint16_t info);
};
class NetLedgerCommonInterfaceMock : public NetLedgerCommonInterface {
public:
    NetLedgerCommonInterfaceMock();
    ~NetLedgerCommonInterfaceMock() override;

    MOCK_METHOD2(LnnSetLocalNumU16Info, int32_t(InfoKey, uint16_t));
};
} // namespace OHOS
#endif // LNN_NET_LEDGER_COMMON_MOCK_H