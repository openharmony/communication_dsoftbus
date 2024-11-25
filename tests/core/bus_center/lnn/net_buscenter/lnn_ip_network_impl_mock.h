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

#ifndef LNN_IP_NETWORK_IMPL_MOCK_H
#define LNN_IP_NETWORK_IMPL_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "auth_interface.h"
#include "bus_center_event.h"
#include "disc_interface.h"
#include "lnn_network_manager.h"
#include "lnn_physical_subnet_manager.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_conn_interface.h"
#include "softbus_protocol_def.h"

namespace OHOS {
class LnnIpNetworkImplInterface {
public:
    LnnIpNetworkImplInterface() {};
    virtual ~LnnIpNetworkImplInterface() {};
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual int32_t LnnRegistPhysicalSubnet(LnnPhysicalSubnet *manager) = 0;
    virtual void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium) = 0;
    virtual bool LnnVisitPhysicalSubnet(LnnVisitPhysicalSubnetCallback callback, void *data) = 0;
    virtual void LnnStopPublish(void) = 0;
    virtual void LnnStopDiscovery(void) = 0;
    virtual void LnnIpAddrChangeEventHandler(void) = 0;
    virtual void AuthStopListening(AuthLinkType type) = 0;
    virtual int32_t TransTdcStopSessionListener(ListenerModule module) = 0;
    virtual int32_t ConnStopLocalListening(const LocalListenerInfo *info) = 0;
    virtual int32_t LnnGetAddrTypeByIfName(const char *ifName, ConnectionAddrType *type) = 0;
    virtual int32_t LnnStartPublish(void) = 0;
    virtual bool LnnIsAutoNetWorkingEnabled(void) = 0;
    virtual int32_t LnnStartDiscovery(void) = 0;
    virtual int32_t AuthStartListening(AuthLinkType type, const char *ip, int32_t port) = 0;
    virtual int32_t TransTdcStartSessionListener(ListenerModule module, const LocalListenerInfo *info) = 0;
    virtual int32_t ConnStartLocalListening(const LocalListenerInfo *info) = 0;
    virtual bool LnnIsLinkReady(const char *iface) = 0;
    virtual void LnnNotifyPhysicalSubnetStatusChanged(const char *ifName, ProtocolType protocolType, void *status) = 0;
    virtual bool LnnVisitNetif(VisitNetifCallback callback, void *data) = 0;
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen) = 0;
    virtual int32_t GetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len) = 0;
    virtual int32_t LnnRegistProtocol(LnnProtocolManager *protocolMgr) = 0;
    virtual int32_t GetWlanIpv4Addr(char *ip, uint32_t size) = 0;
    virtual int32_t ConnCoapStartServerListen(void) = 0;
    virtual void ConnCoapStopServerListen(void) = 0;
};

class LnnIpNetworkImplInterfaceMock : public LnnIpNetworkImplInterface {
public:
    LnnIpNetworkImplInterfaceMock();
    ~LnnIpNetworkImplInterfaceMock() override;
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnRegistPhysicalSubnet, int32_t(LnnPhysicalSubnet *));
    MOCK_METHOD2(DiscLinkStatusChanged, void(LinkStatus, ExchangeMedium));
    MOCK_METHOD2(LnnVisitPhysicalSubnet, bool(LnnVisitPhysicalSubnetCallback, void *));
    MOCK_METHOD0(LnnStopPublish, void(void));
    MOCK_METHOD0(LnnStopDiscovery, void(void));
    MOCK_METHOD0(LnnIpAddrChangeEventHandler, void(void));
    MOCK_METHOD1(AuthStopListening, void(AuthLinkType));
    MOCK_METHOD1(TransTdcStopSessionListener, int32_t(ListenerModule));
    MOCK_METHOD1(ConnStopLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD2(LnnGetAddrTypeByIfName, int32_t(const char *, ConnectionAddrType *));
    MOCK_METHOD0(LnnStartPublish, int32_t(void));
    MOCK_METHOD0(LnnIsAutoNetWorkingEnabled, bool(void));
    MOCK_METHOD0(LnnStartDiscovery, int32_t(void));
    MOCK_METHOD3(AuthStartListening, int32_t(AuthLinkType, const char *, int32_t));
    MOCK_METHOD2(TransTdcStartSessionListener, int32_t(ListenerModule, const LocalListenerInfo *));
    MOCK_METHOD1(ConnStartLocalListening, int32_t(const LocalListenerInfo *));
    MOCK_METHOD1(LnnIsLinkReady, bool(const char *));
    MOCK_METHOD3(LnnNotifyPhysicalSubnetStatusChanged, void(const char *, ProtocolType, void *));
    MOCK_METHOD2(LnnVisitNetif, bool(VisitNetifCallback, void *));
    MOCK_METHOD2(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t));
    MOCK_METHOD4(GetNetworkIpByIfName, int32_t(const char *, char *, char *, uint32_t));
    MOCK_METHOD1(LnnRegistProtocol, int32_t(LnnProtocolManager *));
    MOCK_METHOD2(GetWlanIpv4Addr, int32_t(char *, uint32_t));
    MOCK_METHOD0(ConnCoapStartServerListen, int32_t(void));
    MOCK_METHOD0(ConnCoapStopServerListen, void(void));
    static int32_t ActionOfGetNetworkIpByIfName(const char *ifName, char *ip, char *netmask, uint32_t len);
};
} // namespace OHOS
#endif // LNN_IP_NETWORK_IMPL_MOCK_H