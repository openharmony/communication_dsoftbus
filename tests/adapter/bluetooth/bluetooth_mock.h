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

class BluetoothCommonn
{
public:
    virtual bool EnableBle();
    virtual bool DisableBle();
    virtual bool IsBleEnabled();
    virtual bool GetLocalAddr(unsigned char *mac, unsigned int len);
    virtual bool SetLocalName(unsigned char *localName, unsigned char length);
    virtual int GapRegisterCallbacks(BtGapCallBacks *func);
    virtual bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept);
    virtual bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept);
};

class MockBluetoothCommonn : public BluetoothCommonn
{
public:
    MOCK_METHOD(bool, EnableBle, (), (override));
    MOCK_METHOD(bool, DisableBle, (), (override));
    MOCK_METHOD(bool, IsBleEnabled, (), (override));
    MOCK_METHOD(bool, GetLocalAddr, (unsigned char *mac, unsigned int len), (override));
    MOCK_METHOD(bool, SetLocalName, (unsigned char *localName, unsigned char length), (override));
    MOCK_METHOD(int, GapRegisterCallbacks, (BtGapCallBacks *func), (override));
    MOCK_METHOD(bool, PairRequestReply, (const BdAddr *bdAddr, int transport, bool accept), (override));
    MOCK_METHOD(bool, SetDevicePairingConfirmation, (const BdAddr *bdAddr, int transport, bool accept), (override));
};

// mock symbols, which should be redirected to mocker when linking
extern "C" {
    bool EnableBle(void);
    bool DisableBle(void);
    bool IsBleEnabled(void);
    bool GetLocalAddr(unsigned char *mac, unsigned int len);
    bool SetLocalName(unsigned char *localName, unsigned char length);
    int GapRegisterCallbacks(BtGapCallBacks *func);
    bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept);
    bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept);
}

void InjectMocker(MockBluetoothCommonn *mocker);
BtGapCallBacks *GetBtGapCallBacks();
SoftBusBtStateListener *GetMockBtStateListener();
void CleanupMockState();

// helper functions for assert callback situation
testing::AssertionResult ExpectOnBtStateChanged(int listenerId, int state);
testing::AssertionResult ExpectOnBtAclStateChanged(int listenerId, SoftBusBtAddr &addr, int aclState);

#endif