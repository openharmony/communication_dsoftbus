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

#include "bluetooth_mock.h"

#include <securec.h>

#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static void CleanupBtStateChangedCtx(BtStateChangedCtx &ctx);
static void CleanupAclStateChangedCtx(AclStateChangedCtx &ctx);
static void OnBtStateChanged(int listenerId, int state);
static void OnBtAclStateChanged(int listenerId, const SoftBusBtAddr *addr, int aclState);

MockBluetoothCommonn *MockBluetoothCommonn::targetMocker = nullptr;
BtGapCallBacks MockBluetoothCommonn::btGapCallback = {0};
BtStateChangedCtx MockBluetoothCommonn::btCtx = {0};
AclStateChangedCtx MockBluetoothCommonn::aclCtx = {0};

SoftBusBtStateListener *MockBluetoothCommonn::GetMockBtStateListener()
{
    static SoftBusBtStateListener listener = {
        .OnBtStateChanged = OnBtStateChanged,
        .OnBtAclStateChanged = OnBtAclStateChanged,
    };
    return &listener;
}

BtGapCallBacks *MockBluetoothCommonn::GetBtGapCallBacks()
{
    return &btGapCallback;
}

testing::AssertionResult MockBluetoothCommonn::ExpectOnBtStateChanged(int listenerId, int state)
{
    if (btCtx.calledCnt != 1) {
        return testing::AssertionFailure() << "OnBtStateChanged is not called only once: " << btCtx.calledCnt <<
            ", see log for more details";
    }
    if (btCtx.listenerId != listenerId) {
        return testing::AssertionFailure() << "OnBtStateChanged is call by unexpectedly listenerId," <<
            "want: " << listenerId << ", actual: "<< btCtx.listenerId;
    }
    if (btCtx.state != state) {
        return testing::AssertionFailure() << "OnBtStateChanged is call by unexpectedly state," <<
            "want: " << state << ", actual: "<< btCtx.state;
    }
    return testing::AssertionSuccess();
}

testing::AssertionResult MockBluetoothCommonn::ExpectOnBtAclStateChanged(
    int listenerId, SoftBusBtAddr &addr, int aclState)
{
    if (aclCtx.calledCnt != 1) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is not called only once: " << aclCtx.calledCnt <<
            ", see log for more details";
    }
    if (aclCtx.listenerId != listenerId) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly listenerId," <<
            "want: " << listenerId << ", actual: "<< aclCtx.listenerId;
    }
    if (memcmp(&aclCtx.addrVal, &addr, sizeof(SoftBusBtAddr)) != 0) {
        char wantAddrStr[BT_MAC_LEN] = {0};
        char actualAddrStr[BT_MAC_LEN] = {0};
        if (ConvertBtMacToStr(wantAddrStr, sizeof(wantAddrStr), addr.addr, sizeof(addr.addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert want bt mac to str fail.");
            // continue anyway
        }
        if (ConvertBtMacToStr(actualAddrStr, sizeof(actualAddrStr),
            aclCtx.addrVal.addr, sizeof(aclCtx.addrVal.addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert actual bt mac to str fail.");
            // continue anyway
        }
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly addr," <<
            "want: " << wantAddrStr << ", actual: "<< actualAddrStr;
    }
    if (aclCtx.aclState != aclState) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly aclState," <<
            "want: " << aclState << ", actual: "<< aclCtx.aclState;
    }
    return testing::AssertionSuccess();
}

MockBluetoothCommonn::MockBluetoothCommonn()
{
    MockBluetoothCommonn::targetMocker = this;
}

MockBluetoothCommonn::~MockBluetoothCommonn()
{
    CleanupBtStateChangedCtx(MockBluetoothCommonn::btCtx);
    CleanupAclStateChangedCtx(MockBluetoothCommonn::aclCtx);
}

bool EnableBle(void)
{
    return MockBluetoothCommonn::targetMocker->EnableBle();
}

bool DisableBle(void)
{
    return MockBluetoothCommonn::targetMocker->DisableBle();
}

bool IsBleEnabled()
{
    return MockBluetoothCommonn::targetMocker->IsBleEnabled();
}

bool GetLocalAddr(unsigned char *mac, unsigned int len)
{
    return MockBluetoothCommonn::targetMocker->GetLocalAddr(mac, len);
}

bool SetLocalName(unsigned char *localName, unsigned char length)
{
    return MockBluetoothCommonn::targetMocker->SetLocalName(localName, length);
}

int GapRegisterCallbacks(BtGapCallBacks *func)
{
    MockBluetoothCommonn::btGapCallback = *func;
    return MockBluetoothCommonn::targetMocker->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetoothCommonn::targetMocker->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept)
{
    return MockBluetoothCommonn::targetMocker->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

static void CleanupBtStateChangedCtx(BtStateChangedCtx &ctx)
{
    ctx.calledCnt = 0;
    ctx.listenerId = -1;
    ctx.state = -1;
}

static void CleanupAclStateChangedCtx(AclStateChangedCtx &ctx)
{
    ctx.calledCnt = 0;
    (void)memset_s(&ctx.addrVal, sizeof(SoftBusBtAddr), 0, sizeof(SoftBusBtAddr));
    ctx.listenerId = -1;
    ctx.aclState = -1;
}

static void OnBtStateChanged(int listenerId, int state)
{
    // to avoid being invoked more than once
    if (MockBluetoothCommonn::btCtx.calledCnt++ > 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnBtStateChanged is called again unexpectedly,"
            "first call context is listenerId: %d, state: %d;"
            "current call context is listenerId: %d, state: %d",
            MockBluetoothCommonn::btCtx.listenerId, MockBluetoothCommonn::btCtx.state, listenerId, state);
        return;
    }
    MockBluetoothCommonn::btCtx.listenerId = listenerId;
    MockBluetoothCommonn::btCtx.state = state;
}

static void OnBtAclStateChanged(int listenerId, const SoftBusBtAddr *addr, int aclState)
{
    // to avoid being invoked more than once
    if (MockBluetoothCommonn::aclCtx.calledCnt++ > 0) {
        char firstAddrStr[BT_MAC_LEN] = {0};
        char currentAddrStr[BT_MAC_LEN] = {0};
        if (ConvertBtMacToStr(firstAddrStr, sizeof(firstAddrStr),
            MockBluetoothCommonn::aclCtx.addrVal.addr,
            sizeof(MockBluetoothCommonn::aclCtx.addrVal.addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert first bt mac to str fail.");
            // continue anyway
        }
        
        if (ConvertBtMacToStr(currentAddrStr, sizeof(currentAddrStr), addr->addr, sizeof(addr->addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert current bt mac to str fail.");
            // continue anyway
        }
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnBtAclStateChanged is called again unexpectedly,"
            "first call context is listenerId: %d, addr: %s, aclState: %d;"
            "current call context is listenerId: %d, addr: %s, aclState: %d",
            MockBluetoothCommonn::aclCtx.listenerId, firstAddrStr,
            MockBluetoothCommonn::aclCtx.aclState, listenerId, currentAddrStr, aclState);
        return;
    }
    MockBluetoothCommonn::aclCtx.listenerId = listenerId;
    MockBluetoothCommonn::aclCtx.addrVal = *addr;
    MockBluetoothCommonn::aclCtx.aclState = aclState;
}
