#include "bluetooth_mock.h"

#include <securec.h>
#include "softbus_common.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_utils.h"

static MockBluetoothCommonn *g_target;
static BtGapCallBacks *g_btGapCallback;

struct BtStateChangedCtx
{
    int calledCnt;
    int listenerId;
    int state;
};
struct AclStateChangedCtx
{
    int calledCnt;
    int listenerId;
    // change addr's type from pointer to value on purpose, as it will not require to manage memory
    SoftBusBtAddr addrVal;
    int aclState;
};
static BtStateChangedCtx g_btCtx;
static AclStateChangedCtx g_aclCtx;

bool EnableBle(void)
{
    return g_target->EnableBle();
}

bool DisableBle(void)
{
    return g_target->DisableBle();
}

bool IsBleEnabled()
{
    return g_target->IsBleEnabled();
}

bool GetLocalAddr(unsigned char *mac, unsigned int len)
{
    return g_target->GetLocalAddr(mac, len);
}

bool SetLocalName(unsigned char *localName, unsigned char length)
{
    return g_target->SetLocalName(localName, length);
}

int GapRegisterCallbacks(BtGapCallBacks *func)
{
    g_btGapCallback = func;
    return g_target->GapRegisterCallbacks(func);
}

bool PairRequestReply(const BdAddr *bdAddr, int transport, bool accept)
{
    return g_target->PairRequestReply(bdAddr, transport, accept);
}

bool SetDevicePairingConfirmation(const BdAddr *bdAddr, int transport, bool accept)
{
    return g_target->SetDevicePairingConfirmation(bdAddr, transport, accept);
}

void InjectMocker(MockBluetoothCommonn *mocker)
{
    g_target = mocker;
}

BtGapCallBacks *GetBtGapCallBacks() {
    return g_btGapCallback;
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

void CleanupMockState()
{
    CleanupBtStateChangedCtx(g_btCtx);
    CleanupAclStateChangedCtx(g_aclCtx);
}

testing::AssertionResult ExpectOnBtStateChanged(int listenerId, int state)
{
    if (g_btCtx.calledCnt != 1) {
        return testing::AssertionFailure() << "OnBtStateChanged is not called only once: "<< g_btCtx.calledCnt 
            << ", see log for more details";
    }
    if (g_btCtx.listenerId != listenerId) {
        return testing::AssertionFailure() << "OnBtStateChanged is call by unexpectedly listenerId,"
            << "want: " << listenerId << ", actual: "<< g_btCtx.listenerId;
    }
    if (g_btCtx.state != state) {
        return testing::AssertionFailure() << "OnBtStateChanged is call by unexpectedly state,"
            << "want: " << state << ", actual: "<< g_btCtx.state;
    }
    return testing::AssertionSuccess();
}

testing::AssertionResult ExpectOnBtAclStateChanged(int listenerId, SoftBusBtAddr &addr, int aclState)
{
    if (g_aclCtx.calledCnt != 1) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is not called only once: "<< g_aclCtx.calledCnt 
            << ", see log for more details";
    }
    if (g_aclCtx.listenerId != listenerId) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly listenerId,"
            << "want: " << listenerId << ", actual: "<< g_aclCtx.listenerId;
    }
    if (memcmp(&g_aclCtx.addrVal, &addr, sizeof(SoftBusBtAddr)) != 0) {
        char wantAddrStr[BT_MAC_LEN] = {0};
        char actualAddrStr[BT_MAC_LEN] = {0};
        if (ConvertBtMacToStr(wantAddrStr, sizeof(wantAddrStr), addr.addr, sizeof(addr.addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert want bt mac to str fail.");
            // continue anyway
        }
        if (ConvertBtMacToStr(actualAddrStr, sizeof(actualAddrStr),
            g_aclCtx.addrVal.addr, sizeof(g_aclCtx.addrVal.addr)) != SOFTBUS_OK) {
            SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR, "convert actual bt mac to str fail.");
            // continue anyway
        }
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly addr,"
            << "want: " << wantAddrStr << ", actual: "<< actualAddrStr;
    }
    if (g_aclCtx.aclState != aclState) {
        return testing::AssertionFailure() << "OnBtAclStateChanged is call by unexpectedly aclState,"
            << "want: " << aclState << ", actual: "<< g_aclCtx.aclState;
    }
    return testing::AssertionSuccess();
}

static void OnBtStateChanged(int listenerId, int state)
{
    // to avoid being invoked more than once
    if (g_btCtx.calledCnt++ > 0) {
        SoftBusLog(SOFTBUS_LOG_COMM, SOFTBUS_LOG_ERROR,
            "OnBtStateChanged is called again unexpectedly,"
            "first call context is listenerId: %d, state: %d;"
            "current call context is listenerId: %d, state: %d",
            g_btCtx.listenerId, g_btCtx.state, listenerId, state);
        return;
    }
    g_btCtx.listenerId = listenerId;
    g_btCtx.state = state;
}

static void OnBtAclStateChanged(int listenerId, const SoftBusBtAddr *addr, int aclState)
{
    char firstAddrStr[BT_MAC_LEN] = {0};
    char currentAddrStr[BT_MAC_LEN] = {0};
    // to avoid being invoked more than once
    if (g_aclCtx.calledCnt++ > 0) {
        if (ConvertBtMacToStr(firstAddrStr, sizeof(firstAddrStr),
            g_aclCtx.addrVal.addr, sizeof(g_aclCtx.addrVal.addr)) != SOFTBUS_OK) {
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
            g_aclCtx.listenerId, firstAddrStr, g_aclCtx.aclState, listenerId, currentAddrStr, aclState);
        return;
    }
    g_aclCtx.listenerId = listenerId;
    g_aclCtx.addrVal = *addr;
    g_aclCtx.aclState = aclState;
}

SoftBusBtStateListener *GetMockBtStateListener()
{
    static SoftBusBtStateListener listener = {
        .OnBtStateChanged = OnBtStateChanged,
        .OnBtAclStateChanged = OnBtAclStateChanged,
    };
    return &listener;
}
