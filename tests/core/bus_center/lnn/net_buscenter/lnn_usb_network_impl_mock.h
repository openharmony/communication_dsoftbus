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

#ifndef LNN_USB_NETWORK_IMPL_MOCK_H
#define LNN_USB_NETWORK_IMPL_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_network_manager.h"
#include "lnn_node_info.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"

namespace OHOS {
class LnnUsbNetworkImplInterface {
public:
    LnnUsbNetworkImplInterface() {};
    virtual ~LnnUsbNetworkImplInterface() {};
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager) = 0;
    virtual void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium, int32_t ifnameIdx) = 0;
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data) = 0;
    virtual void LnnIpAddrChangeEventHandler(void) = 0;
    virtual void AuthStopListening(AuthLinkType type) = 0;
    virtual int32_t TransTdcStopSessionListener(ListenerModule module) = 0;
    virtual int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type) = 0;
    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port) = 0;
    virtual int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info) = 0;
    virtual void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status) = 0;
    virtual bool LnnVisitNetif(VisitNetifCallback callback, void *data) = 0;
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen, bool hasMcuRequestDisable) = 0;
    virtual int32_t GetNetworkIpv6ByIfName(const char *ifName, char *ip, uint32_t len) = 0;
    virtual int32_t LnnRegistProtocol(LnnProtocolManager *protocolMgr) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info) = 0;
    virtual int32_t LnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx) = 0;
    virtual int32_t LnnGetLocalNumInfoByIfnameIdx(InfoKey key, int32_t *info, int32_t ifIdx) = 0;
    virtual int32_t LnnSetLocalStrInfoByIfnameIdx(InfoKey key, const char *info, int32_t ifIdx) = 0;
    virtual int32_t LnnSetLocalNumInfoByIfnameIdx(InfoKey key, int32_t info, int32_t ifIdx) = 0;
};

class LnnUsbNetworkImplInterfaceMock : public LnnUsbNetworkImplInterface {
public:
    LnnUsbNetworkImplInterfaceMock();
    ~LnnUsbNetworkImplInterfaceMock() override;
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnRegistPhysicalSubnet, int32_t(LnnPhysicalSubnet *));
    MOCK_METHOD3(DiscLinkStatusChanged, void(LinkStatus, ExchangeMedium, int32_t));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool(LnnVisitPhysicalSubnetCallback, void *));
    MOCK_METHOD0(LnnIpAddrChangeEventHandler, void(void));
    MOCK_METHOD1(AuthStopListening, void(AuthLinkType));
    MOCK_METHOD1(TransTdcStopSessionListener, int32_t(ListenerModule));
    MOCK_METHOD2(LnnGetAddrTypeByIfName, int32_t(const char *, ConnectionAddrType *));
    MOCK_METHOD3(AuthStartListening, int32_t(AuthLinkType, const char *, int32_t));
    MOCK_METHOD2(TransTdcStartSessionListener, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD3(LnnNotifyPhysicalSubnetStatusChanged, void(const char *, ProtocolType, void *));
    MOCK_METHOD2(LnnVisitNetif, bool(VisitNetifCallback, void *));
    MOCK_METHOD3(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t, bool));
    MOCK_METHOD3(GetNetworkIpv6ByIfName, int32_t(const char *, char *, uint32_t));
    MOCK_METHOD1(LnnRegistProtocol, int32_t(LnnProtocolManager *));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t(InfoKey, uint32_t *));
    MOCK_METHOD2(LnnSetNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t(uint32_t *, NetCapability));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t(InfoKey, int32_t));
    MOCK_METHOD4(LnnGetLocalStrInfoByIfnameIdx, int32_t(InfoKey, char *, uint32_t, int32_t));
    MOCK_METHOD3(LnnGetLocalNumInfoByIfnameIdx, int32_t(InfoKey, int32_t *, int32_t));
    MOCK_METHOD3(LnnSetLocalStrInfoByIfnameIdx, int32_t(InfoKey, const char *, int32_t));
    MOCK_METHOD3(LnnSetLocalNumInfoByIfnameIdx, int32_t(InfoKey, int32_t, int32_t));
    static int32_t ActionOfGetNetworkIpv6ByIfName(const char *ifName, char *ip, uint32_t len);
    static int32_t ActionOfGetNetworkIpv6ByIfName2(const char *ifName, char *ip, uint32_t len);
    static int32_t ActionOfLnnGetLocalStrInfoByIfnameIdx(InfoKey key, char *info, uint32_t len, int32_t ifIdx);
};
} // namespace OHOS
#endif // LNN_USB_NETWORK_IMPL_MOCK_H