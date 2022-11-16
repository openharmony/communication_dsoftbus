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

#ifndef BLUETOOTH_MOCK_H
#define BLUETOOTH_MOCK_H

#include "gmock/gmock.h"
#include "ohos_bt_gap.h"

#include "softbus_adapter_bt_common.h"

// declare mock symbols explicitly which hava C implement, redirected to mocker when linking
class BluetoothCommonn {
public:
    virtual bool EnableBle() = 0;
    virtual bool DisableBle() = 0;
    virtual bool IsBleEnabled() = 0;
    virtual bool GetLocalAddr(unsigned char *mac, unsigned int len) = 0;
    virtual bool SetLocalName(unsigned char *localName, unsigned char length) = 0;
    virtual int GapRegisterCallbacks(BtGapCallBacks *func) = 0;
    virtual bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept) = 0;
    virtual bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept) = 0;
};

struct BtStateChangedCtx {
    int calledCnt;
    int listenerId;
    int state;
};

struct AclStateChangedCtx {
    int calledCnt;
    int listenerId;
    // change addr's type from pointer to value on purpose, as it will not require to manage memory
    SoftBusBtAddr addrVal;
    int aclState;
};

class MockBluetoothCommonn : public BluetoothCommonn {
public:
    static MockBluetoothCommonn *targetMocker;
    static BtGapCallBacks btGapCallback;
    static BtStateChangedCtx btCtx;
    static AclStateChangedCtx aclCtx;

    static SoftBusBtStateListener *GetMockBtStateListener();
    static BtGapCallBacks *GetBtGapCallBacks();
    // helper functions for assert callback situation
    static testing::AssertionResult ExpectOnBtStateChanged(int listenerId, int state);
    static testing::AssertionResult ExpectOnBtAclStateChanged(int listenerId, SoftBusBtAddr &addr, int aclState);

    MockBluetoothCommonn();
    ~MockBluetoothCommonn();

    MOCK_METHOD(bool, EnableBle, (), (override));
    MOCK_METHOD(bool, DisableBle, (), (override));
    MOCK_METHOD(bool, IsBleEnabled, (), (override));
    MOCK_METHOD(bool, GetLocalAddr, (unsigned char *mac, unsigned int len), (override));
    MOCK_METHOD(bool, SetLocalName, (unsigned char *localName, unsigned char length), (override));
    MOCK_METHOD(int, GapRegisterCallbacks, (BtGapCallBacks *func), (override));
    MOCK_METHOD(bool, PairRequestReply, (const BdAddr *bdAddr, int transport, bool accept), (override));
    MOCK_METHOD(bool, SetDevicePairingConfirmation, (const BdAddr *bdAddr, int transport, bool accept), (override));
};

#endif