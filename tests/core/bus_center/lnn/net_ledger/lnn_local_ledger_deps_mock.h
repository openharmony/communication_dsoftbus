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

#ifndef LNN_LOCAL_LEDGER_DEPS_MOCK_H
#define LNN_LOCAL_LEDGER_DEPS_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "lnn_device_info.h"
#include "lnn_net_capability.h"
#include "softbus_adapter_crypto.h"
#include "bus_center_adapter.h"
#include "lnn_p2p_info.h"
#include "softbus_adapter_thread.h"
#include "softbus_hidumper_buscenter.h"
#include "lnn_ohos_account.h"

namespace OHOS {
class LocalLedgerDepsInterface {
public:
    LocalLedgerDepsInterface() {};
    virtual ~LocalLedgerDepsInterface() {};

    virtual uint32_t LnnGetNetCapabilty(void);
    virtual int32_t SoftBusGenerateRandomArray(unsigned char *randStr, uint32_t len);
    virtual int32_t GetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len);
    virtual int32_t LnnInitLocalP2pInfo(NodeInfo *info);
    virtual int32_t SoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb);
    virtual int32_t LnnInitOhosAccount(void);
};
class LocalLedgerDepsInterfaceMock : public LocalLedgerDepsInterface {
public:
    LocalLedgerDepsInterfaceMock();
    ~LocalLedgerDepsInterfaceMock() override;
    MOCK_METHOD0(LnnGetNetCapabilty, uint32_t ());
    MOCK_METHOD2(SoftBusGenerateRandomArray, int32_t (unsigned char *, uint32_t));
    MOCK_METHOD3(GetCommonDevInfo, int32_t (const CommonDeviceKey, char *, uint32_t));
    MOCK_METHOD1(LnnInitLocalP2pInfo, int32_t (NodeInfo *info));
    MOCK_METHOD2(SoftBusRegBusCenterVarDump, int32_t (char *, SoftBusVarDumpCb));
    MOCK_METHOD0(LnnInitOhosAccount, int32_t ());

    static int32_t LedgerGetCommonDevInfo(const CommonDeviceKey key, char *value, uint32_t len);
    static int32_t LedgerSoftBusRegBusCenterVarDump(char *dumpVar, SoftBusVarDumpCb cb);
};
} // namespace OHOS
#endif // LNN_LOCAL_LEDGER_DEPS_MOCK_H
