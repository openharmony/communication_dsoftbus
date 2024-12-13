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

#ifndef LNN_NETWORK_MANAGER_MOCK_H
#define LNN_NETWORK_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "disc_interface.h"
#include "form/lnn_event_form.h"
#include "lnn_async_callback_utils.h"
#include "lnn_connection_fsm.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_ohos_account.h"
#include "lnn_network_manager.h"
#include "message_handler.h"
#include "softbus_adapter_bt_common.h"
#include "softbus_common.h"
#include "softbus_config_type.h"

namespace OHOS {
class LnnNetworkManagerInterface {
public:
    LnnNetworkManagerInterface() {};
    virtual ~LnnNetworkManagerInterface() {};
    virtual int32_t RegistIPProtocolManager(void) = 0;
    virtual int32_t LnnInitPhysicalSubnetManager(void) = 0;
    virtual void LnnOnOhosAccountChanged(void) = 0;
    virtual void LnnStopDiscovery(void) = 0;
    virtual int32_t LnnStartDiscovery(void) = 0;
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len) = 0;
    virtual void DiscLinkStatusChanged(LinkStatus status, ExchangeMedium medium) = 0;
    virtual void LnnStopPublish(void) = 0;
    virtual int32_t LnnStartPublish(void) = 0;
    virtual void LnnUpdateOhosAccount(UpdateAccountReason reason) = 0;
    virtual void LnnOnOhosAccountLogout(void) = 0;
    virtual bool LnnGetOnlineStateById(const char *id, IdCategory type) = 0;
    virtual int32_t LnnNotifyDiscoveryDevice(
        const ConnectionAddr *addr, const LnnDfxDeviceInfoReport *infoReport, bool isNeedConnect) = 0;
    virtual int32_t LnnRequestLeaveByAddrType(const bool *type, uint32_t typeLen) = 0;
    virtual int32_t LnnAsyncCallbackDelayHelper(
        SoftBusLooper *looper, LnnAsyncCallbackFunc callback, void *para, uint64_t delayMillis) = 0;
    virtual int32_t LnnRegisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void LnnNotifyOOBEStateChangeEvent(SoftBusOOBEState state) = 0;
    virtual void LnnNotifyAccountStateChangeEvent(SoftBusAccountState state) = 0;
    virtual void LnnDeinitPhysicalSubnetManager(void) = 0;
    virtual void LnnUnregisterEventHandler(LnnEventType event, LnnEventHandler handler) = 0;
    virtual void DfxRecordTriggerTime(LnnTriggerReason reason, LnnEventLnnStage stage) = 0;
};

class LnnNetworkManagerInterfaceMock : public LnnNetworkManagerInterface {
public:
    LnnNetworkManagerInterfaceMock();
    ~LnnNetworkManagerInterfaceMock() override;
    MOCK_METHOD0(RegistIPProtocolManager, int32_t(void));
    MOCK_METHOD0(LnnInitPhysicalSubnetManager, int32_t(void));
    MOCK_METHOD0(LnnOnOhosAccountChanged, void(void));
    MOCK_METHOD0(LnnStopDiscovery, void(void));
    MOCK_METHOD0(LnnStartDiscovery, int32_t(void));
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD2(DiscLinkStatusChanged, void(LinkStatus, ExchangeMedium));
    MOCK_METHOD0(LnnStopPublish, void(void));
    MOCK_METHOD0(LnnStartPublish, int32_t(void));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(UpdateAccountReason));
    MOCK_METHOD0(LnnOnOhosAccountLogout, void(void));
    MOCK_METHOD2(LnnGetOnlineStateById, bool(const char *, IdCategory));
    MOCK_METHOD3(LnnNotifyDiscoveryDevice, int32_t(const ConnectionAddr *, const LnnDfxDeviceInfoReport *, bool));
    MOCK_METHOD2(LnnRequestLeaveByAddrType, int32_t(const bool *, uint32_t));
    MOCK_METHOD4(LnnAsyncCallbackDelayHelper, int32_t(SoftBusLooper *, LnnAsyncCallbackFunc, void *, uint64_t));
    MOCK_METHOD2(LnnRegisterEventHandler, int32_t(LnnEventType, LnnEventHandler));
    MOCK_METHOD1(LnnNotifyOOBEStateChangeEvent, void(SoftBusOOBEState));
    MOCK_METHOD1(LnnNotifyAccountStateChangeEvent, void(SoftBusAccountState));
    MOCK_METHOD0(LnnDeinitPhysicalSubnetManager, void(void));
    MOCK_METHOD2(LnnUnregisterEventHandler, void(LnnEventType, LnnEventHandler));
    MOCK_METHOD2(DfxRecordTriggerTime, void(LnnTriggerReason, LnnEventLnnStage));
};
} // namespace OHOS
#endif // LNN_NETWORK_MANAGER_MOCK_H