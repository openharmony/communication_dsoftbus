/*
 * Copyright (c) 2022-2025 Huawei Device Co., Ltd.
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

#ifndef NET_WORK_MOCK_H
#define NET_WORK_MOCK_H

#include "gtest/gtest.h"
#include <arpa/inet.h>
#include <gmock/gmock.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <mutex>
#include <net/if.h>
#include <securec.h>
#include <stdint.h>
#include <sys/ioctl.h>
#include <unistd.h>

#include "bus_center_event.h"
#include "lnn_async_callback_utils.h"
#include "lnn_network_manager.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_adapter_sle_common.h"
#include "softbus_adapter_socket.h"
#include "softbus_base_listener.h"
#include "softbus_conn_interface.h"
#include "softbus_config_type.h"
#include "softbus_wifi_api_adapter.h"

namespace OHOS {
class NetworkInterface {
public:
    NetworkInterface() {};
    virtual ~NetworkInterface() {};

    virtual int32_t SoftBusSocketCreate(int32_t domain, int32_t type, int32_t protocol, int32_t *socketFd) = 0;
    virtual int32_t SoftBusSocketSetOpt(
        int32_t socketFd, int32_t level, int32_t optName, const void *optVal, int32_t optLen) = 0;
    virtual int32_t SoftBusSocketClose(int32_t socketFd) = 0;
    virtual int32_t SoftBusSocketBind(int32_t socketFd, SoftBusSockAddr *addr, int32_t addrLen) = 0;
    virtual int32_t LnnGetNetIfTypeByName(const char *ifName, LnnNetIfType *type) = 0;
    virtual void LnnNotifyAddressChangedEvent(const char *ifName) = 0;
    virtual int32_t SoftBusSocketRecv(int32_t socketFd, void *buf, uint32_t len, int32_t flags) = 0;
    virtual int32_t LnnAsyncCallbackHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para) = 0;
    virtual void LnnNotifyBtAclStateChangeEvent(const char *btMac, SoftBusBtAclState state) = 0;
    virtual int32_t ConvertBtMacToStr(char *strMac, uint32_t strMacLen, const uint8_t *binMac, uint32_t binMacLen) = 0;
    virtual int32_t SoftBusAddBtStateListener(const SoftBusBtStateListener *listener, int32_t *listenerId) = 0;
    virtual int SoftBusAddSleStateListener(const SoftBusSleStateListener *listener, int *listenerId) = 0;
    virtual bool IsSleEnabled() = 0;
    virtual void SoftBusRemoveSleStateListener(int listenerId) = 0;
    virtual void LnnNotifySleStateChangeEvent(void *state) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual void LnnNotifyBtStateChangeEvent(void *state) = 0;
    virtual void LnnNotifyNetlinkStateChangeEvent(NetManagerIfNameState state, const char *ifName) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(SoftBusLooper *looper, LnnAsyncCallbackFunc callback,
        void *para, uint64_t delayMillis) = 0;
    virtual int32_t StartBaseClient(ListenerModule module, const SoftbusBaseListener *listener) = 0;
    virtual int32_t AddTrigger(ListenerModule module, int32_t fd, TriggerType trigger) = 0;
    virtual int32_t LnnGetLocalNumU32Info(InfoKey key, uint32_t *info) = 0;
    virtual int32_t LnnSetLocalNumU32Info(InfoKey key, uint32_t info) = 0;
    virtual SoftBusBand SoftBusGetLinkBand(void) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type) = 0;
};
class NetworkInterfaceMock : public NetworkInterface {
public:
    NetworkInterfaceMock();
    ~NetworkInterfaceMock() override;

    MOCK_METHOD4(SoftBusSocketCreate, int32_t(int32_t, int32_t, int32_t, int32_t *));
    MOCK_METHOD5(SoftBusSocketSetOpt, int32_t(int32_t, int32_t, int32_t, const void *, int32_t));
    MOCK_METHOD1(SoftBusSocketClose, int32_t(int32_t));
    MOCK_METHOD3(SoftBusSocketBind, int32_t(int32_t, SoftBusSockAddr *, int32_t));
    MOCK_METHOD2(LnnGetNetIfTypeByName, int32_t(const char *, LnnNetIfType *));
    MOCK_METHOD1(LnnNotifyAddressChangedEvent, void(const char *));
    MOCK_METHOD4(SoftBusSocketRecv, int32_t(int32_t, void *, uint32_t, int32_t));
    MOCK_METHOD3(LnnAsyncCallbackHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *));
    MOCK_METHOD2(LnnNotifyBtAclStateChangeEvent, void(const char *, SoftBusBtAclState));
    MOCK_METHOD4(ConvertBtMacToStr, int32_t(char *, uint32_t, const uint8_t *, uint32_t));
    MOCK_METHOD2(SoftBusAddBtStateListener, int(const SoftBusBtStateListener *, int32_t *));
    MOCK_METHOD2(SoftBusAddSleStateListener, int(const SoftBusSleStateListener *, int *));
    MOCK_METHOD0(IsSleEnabled, bool());
    MOCK_METHOD1(SoftBusRemoveSleStateListener, void(int));
    MOCK_METHOD1(LnnNotifySleStateChangeEvent, void(void *));
    MOCK_METHOD3(SoftbusGetConfig, int(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD1(LnnNotifyBtStateChangeEvent, void(void *));
    MOCK_METHOD2(LnnNotifyNetlinkStateChangeEvent, void(NetManagerIfNameState, const char *));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t (SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(StartBaseClient, int32_t (ListenerModule module, const SoftbusBaseListener *listener));
    MOCK_METHOD3(AddTrigger, int32_t (ListenerModule module, int32_t fd, TriggerType trigger));
    MOCK_METHOD2(LnnGetLocalNumU32Info, int32_t (InfoKey, uint32_t *));
    MOCK_METHOD2(LnnSetLocalNumU32Info, int32_t (InfoKey key, uint32_t info));
    MOCK_METHOD0(SoftBusGetLinkBand, SoftBusBand ());
    MOCK_METHOD2(LnnSetNetCapability, int32_t (uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t(uint32_t *, NetCapability));
};
} // namespace OHOS
#endif // NET_WORK_MOCK_H