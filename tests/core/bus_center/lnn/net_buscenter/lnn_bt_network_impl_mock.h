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

#ifndef LNN_BT_NETWORK_IMPL_MOCK_H
#define LNN_BT_NETWORK_IMPL_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_protocol_def.h"

namespace OHOS {
class LnnBtNetworkImplInterface {
public:
    LnnBtNetworkImplInterface() {};
    virtual ~LnnBtNetworkImplInterface() {};
    virtual int32_t LnnRequestLeaveSpecific(const char *networkId, ConnectionAddrType addrType) = 0;
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBtMacAddr(SoftBusBtAddr *mac) = 0;
    virtual int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type) = 0;
    virtual bool LnnVisitNetif(VisitNetifCallback callback, void *data) = 0;
    virtual int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager) = 0;
    virtual void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status) = 0;
};

class LnnBtNetworkImplInterfaceMock : public LnnBtNetworkImplInterface {
public:
    LnnBtNetworkImplInterfaceMock();
    ~LnnBtNetworkImplInterfaceMock() override;
    MOCK_METHOD2(LnnRequestLeaveSpecific, int32_t(const char *, ConnectionAddrType));
    MOCK_METHOD2(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t));
    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD1(SoftBusGetBtMacAddr, int32_t(SoftBusBtAddr *));
    MOCK_METHOD4(ConvertBtMacToStr, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(LnnGetNetIfTypeByName, int32_t(const char *, LnnNetIfType *));
    MOCK_METHOD2(LnnVisitNetif, bool(VisitNetifCallback, void *));
    MOCK_METHOD1(LnnRegistPhysicalSubnet, int32_t(LnnPhysicalSubnet *));
    MOCK_METHOD3(LnnNotifyPhysicalSubnetStatusChanged, void(const char *, ProtocolType, void *));
    static int32_t ActionOfLnnGetNetIfTypeByNameBr(const char *ifName, LnnNetIfType *type);
    static int32_t ActionOfLnnGetNetIfTypeByNameBle(const char *ifName, LnnNetIfType *type);
};
} // namespace OHOS
#endif // LNN_BT_NETWORK_IMPL_MOCK_H