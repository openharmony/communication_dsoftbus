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

#ifndef HEARTBEAT_CTRL_DEPS_H
#define HEARTBEAT_CTRL_DEPS_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_event.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_utils.h"
#include "lnn_ohos_account.h"
#include "softbus_common.h"

namespace OHOS {
class HeartBeatCtrlDepsInterface {
public:
    HeartBeatCtrlDepsInterface() {};
    virtual ~HeartBeatCtrlDepsInterface() {};

    virtual void LnnNotifyNetworkStateChanged(SoftBusNetworkState state) = 0;
    virtual int32_t AuthFlushDevice(const char *uuid) = 0;
    virtual int32_t SoftBusGetBtState(void) = 0;
    virtual int32_t SoftBusGetBrState(void) = 0;
    virtual void RestartCoapDiscovery(void) = 0;
    virtual ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type) = 0;
    virtual bool IsEnableSoftBusHeartbeat(void) = 0;
    virtual void LnnUpdateOhosAccount(UpdateAccountReason reason) = 0;
    virtual int32_t LnnHbMediumMgrSetParam(void *param) = 0;
    virtual bool LnnIslocalSupportBurstFeature(void) = 0;
    virtual int32_t AuthSendKeepaliveOption(const char *uuid, ModeCycle cycle) = 0;
    virtual int32_t LnnGenerateCeParams(void) = 0;
};
class HeartBeatCtrlDepsInterfaceMock : public HeartBeatCtrlDepsInterface {
public:
    HeartBeatCtrlDepsInterfaceMock();
    ~HeartBeatCtrlDepsInterfaceMock() override;

    MOCK_METHOD1(LnnNotifyNetworkStateChanged, void(SoftBusNetworkState));
    MOCK_METHOD1(AuthFlushDevice, int32_t(const char *));
    MOCK_METHOD0(SoftBusGetBtState, int32_t(void));
    MOCK_METHOD0(SoftBusGetBrState, int32_t(void));
    MOCK_METHOD0(RestartCoapDiscovery, void(void));
    MOCK_METHOD1(LnnConvertHbTypeToConnAddrType, ConnectionAddrType(LnnHeartbeatType));
    MOCK_METHOD0(IsEnableSoftBusHeartbeat, bool(void));
    MOCK_METHOD1(LnnUpdateOhosAccount, void(UpdateAccountReason));
    MOCK_METHOD1(LnnHbMediumMgrSetParam, int32_t(void *));
    MOCK_METHOD0(LnnIslocalSupportBurstFeature, bool(void));
    MOCK_METHOD2(AuthSendKeepaliveOption, int32_t(const char *, ModeCycle));
    MOCK_METHOD0(LnnGenerateCeParams, int32_t(void));
};
} // namespace OHOS
#endif // HEARTBEAT_CTRL_DEPS_H
