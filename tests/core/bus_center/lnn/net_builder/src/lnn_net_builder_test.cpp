/*
 * Copyright (c) 2022-2023 Huawei Device Co., Ltd.
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

#include <gtest/gtest.h>
#include <securec.h>

#include "bus_center_event.h"
#include "bus_center_manager.h"
#include "lnn_local_net_ledger.h"
#include "lnn_net_builder.h"
#include "lnn_net_builder_process.h"
#include "message_handler.h"
#include "softbus_common.h"
#include "softbus_error_code.h"

constexpr char NETWORKID[] = "ABCDEFG";
constexpr char OLD_NETWORKID[] = "ABCDEFG";
constexpr char MASTER_UDID[] = "0123456";
constexpr uint16_t CONN_FSM_ID = 1;
constexpr int32_t MASTER_WEIGHT = 1;
constexpr uint32_t TYPE_LEN = 1;
constexpr uint32_t TYPE_LENTH = 6;
constexpr char IP[IP_STR_MAX_LEN] = "127.0.0.1";
constexpr uint16_t PORT = 1000;
constexpr char PEERUID[MAX_ACCOUNT_HASH_LEN] = "021315ASD";
constexpr uint8_t MSG[] = "123456BNHFCF";
constexpr int64_t AUTH_ID = 10;
constexpr uint32_t REQUEST_ID = 10;
constexpr uint16_t CHANNEL_ID = 2050;

#define SOFTBUS_SUB_SYSTEM        203
#define SOFTBUS_AUTH_MODULE       3
#define HICHAIN_ERROR_KEY_NOEXIST (-((SOFTBUS_SUB_SYSTEM << 21) | (SOFTBUS_AUTH_MODULE << 16) | 0x0101))

namespace OHOS {
using namespace testing::ext;

class LNNNetBuilderTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNNetBuilderTest::SetUpTestCase()
{
    LooperInit();
}

void LNNNetBuilderTest::TearDownTestCase()
{
    LooperDeinit();
}

void LNNNetBuilderTest::SetUp()
{
    LnnInitBusCenterEvent();
}

void LNNNetBuilderTest::TearDown()
{
    LnnDeinitNetBuilder();
    LnnDeinitBusCenterEvent();
}

static void OnLnnServerJoinExtCb(const ConnectionAddr *addr, int32_t returnRet)
{
    (void)addr;
    return;
}

/*
 * @tc.name: LNN_NOTIFY_DISCOVERY_DEVICE_TEST_001
 * @tc.desc: test LnnNotifyDiscoveryDevice
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_NOTIFY_DISCOVERY_DEVICE_TEST_001, TestSize.Level0)
{
    ConnectionAddr target = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    LnnDfxDeviceInfoReport infoReport;
    (void)memset_s(&infoReport, sizeof(LnnDfxDeviceInfoReport), 0, sizeof(LnnDfxDeviceInfoReport));
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    int32_t ret = LnnNotifyDiscoveryDevice(&target, &infoReport, false);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnNotifyDiscoveryDevice(nullptr, &infoReport, false);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_REQUEST_LEAVE_BY_ADDRTYPE_TEST_001
 * @tc.desc: test LnnRequestLeaveByAddrType
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_REQUEST_LEAVE_BY_ADDRTYPE_TEST_001, TestSize.Level0)
{
    const bool type[CONNECTION_ADDR_MAX] = { true, true, true, true, true };
    int32_t ret = LnnRequestLeaveByAddrType(type, CONNECTION_ADDR_MAX);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveByAddrType(nullptr, TYPE_LENTH);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnRequestLeaveByAddrType(type, TYPE_LEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnRequestLeaveByAddrType(type, TYPE_LENTH);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REQUEST_LEAVE_SPECIFIC_TEST_001
 * @tc.desc: test LnnRequestLeaveSpecific
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_REQUEST_LEAVE_SPECIFIC_TEST_001, TestSize.Level0)
{
    char *networkId = nullptr;
    int32_t ret = LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnRequestLeaveSpecific(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveSpecific(NETWORKID, CONNECTION_ADDR_WLAN);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REQUEST_LEAVE_INVALID_CONN_TEST_001
 * @tc.desc: test LnnRequestLeaveInvalidConn
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_REQUEST_LEAVE_INVALID_CONN_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnRequestLeaveInvalidConn(OLD_NETWORKID, CONNECTION_ADDR_WLAN, NETWORKID);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestLeaveInvalidConn(OLD_NETWORKID, CONNECTION_ADDR_WLAN, NETWORKID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REQUEST_CLEAN_CONN_FSM_TEST_001
 * @tc.desc: test LnnRequestCleanConnFsm
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_REQUEST_CLEAN_CONN_FSM_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnRequestCleanConnFsm(CONN_FSM_ID);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRequestCleanConnFsm(CONN_FSM_ID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NOTIFY_NODE_STATE_CHANGED_TEST_001
 * @tc.desc: test LnnNotifyNodeStateChanged
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_NOTIFY_NODE_STATE_CHANGED_TEST_001, TestSize.Level0)
{
    ConnectionAddr target = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    memcpy_s(target.peerUid, MAX_ACCOUNT_HASH_LEN, PEERUID, strlen(PEERUID));
    memcpy_s(target.info.ip.ip, IP_STR_MAX_LEN, IP, strlen(IP));
    int32_t ret = LnnNotifyNodeStateChanged(&target);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnNotifyNodeStateChanged(&target);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_NOTIFY_MASTER_ELECT_TEST_001
 * @tc.desc: test LnnNotifyMasterElect
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_NOTIFY_MASTER_ELECT_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnNotifyMasterElect(NETWORKID, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    char *networkId = nullptr;
    ret = LnnNotifyMasterElect(networkId, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnNotifyMasterElect(NETWORKID, MASTER_UDID, MASTER_WEIGHT);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_UPDATE_NODE_ADDR_TEST_001
 * @tc.desc: test LnnUpdateNodeAddr
 * @tc.type: FUNC
 * @tc.require: I5PRUD
 */
HWTEST_F(LNNNetBuilderTest, LNN_UPDATE_NODE_ADDR_TEST_001, TestSize.Level0)
{
    char *addr = nullptr;
    int32_t ret = LnnUpdateNodeAddr(addr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnUpdateNodeAddr(MASTER_UDID);
    EXPECT_TRUE(ret == SOFTBUS_LOCK_ERR);
    ret = LnnInitLocalLedger();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnUpdateNodeAddr(MASTER_UDID);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SYNC_OFFLINE_COMPLETE_TEST_001
 * @tc.desc: test LnnSyncOfflineComplete
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_SYNC_OFFLINE_COMPLETE_TEST_001, TestSize.Level0)
{
    uint32_t len = TYPE_LEN;
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CAPABILITY, NETWORKID, MSG, len);
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CAPABILITY, nullptr, MSG, len);
    LnnSyncOfflineComplete(LNN_INFO_TYPE_CAPABILITY, NETWORKID, MSG, len);
}

/*
 * @tc.name: LNN_SERVER_LEAVE_TEST_001
 * @tc.desc: test LnnServerLeave
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_SERVER_LEAVE_TEST_001, TestSize.Level0)
{
    int32_t ret = LnnServerLeave(NETWORKID, "pkaName");
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerLeave(NETWORKID, "pkaName");
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerLeave(nullptr, "pkaName");
    EXPECT_TRUE(ret == SOFTBUS_MALLOC_ERR);
}

/*
 * @tc.name: LNN_SERVER_JOIN_TEST_001
 * @tc.desc: test LnnServerJoin
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_SERVER_JOIN_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, IP);
    int32_t ret = LnnServerJoin(&addr, "pkgName");
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerJoin(&addr, "pkgName");
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerJoin(nullptr, "pkgName");
    EXPECT_TRUE(ret == SOFTBUS_MALLOC_ERR);
    ret = LnnServerJoin(&addr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_MALLOC_ERR);
}

/*
 * @tc.name: LNN_SERVER_JOIN_EXT_TEST_001
 * @tc.desc: test LnnServerJoinExt
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_SERVER_JOIN_EXT_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_SESSION, .info.session.channelId = CHANNEL_ID };
    LnnServerJoinExtCallBack cb = { .lnnServerJoinExtCallback = OnLnnServerJoinExtCb };
    int32_t ret = LnnServerJoinExt(&addr, &cb);
    EXPECT_TRUE(ret == SOFTBUS_NO_INIT);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnServerJoinExt(&addr, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnServerJoinExt(nullptr, &cb);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnServerJoinExt(&addr, nullptr);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: FIND_REQUEST_ID_BY_ADDR_TEST_001
 * @tc.desc: test FindRequestIdByAddr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, FIND_REQUEST_ID_BY_ADDR_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, IP);
    uint32_t requestId;
    uint32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = FindRequestIdByAddr(nullptr, &requestId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/*
 * @tc.name: FIND_NODE_INFO_BY_RQUESTID_TEST_001
 * @tc.desc: test FindNodeInfoByRquestId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, FIND_NODE_INFO_BY_RQUESTID_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, IP);
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    NodeInfo *info = FindNodeInfoByRquestId(REQUEST_ID);
    EXPECT_TRUE(info == nullptr);
}

/*
 * @tc.name: LNN_GET_VERIFY_CALLBACK_TEST_001
 * @tc.desc: test three verify callback
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_GET_VERIFY_CALLBACK_TEST_001, TestSize.Level0)
{
    ConnectionAddr addr = { .type = CONNECTION_ADDR_WLAN, .info.ip.port = PORT };
    (void)strcpy_s(addr.info.ip.ip, IP_STR_MAX_LEN, IP);
    NodeInfo *info = nullptr;
    NodeInfo info1;
    int32_t ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    AuthVerifyCallback *authVerifyCallback = LnnGetVerifyCallback();
    AuthHandle authHandle = { .authId = AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    authVerifyCallback->onVerifyPassed(REQUEST_ID, authHandle, info);
    authVerifyCallback->onVerifyPassed(REQUEST_ID, authHandle, &info1);
    authVerifyCallback = LnnGetReAuthVerifyCallback();
    authVerifyCallback->onVerifyPassed(REQUEST_ID, authHandle, info);
    authVerifyCallback->onVerifyPassed(REQUEST_ID, authHandle, &info1);
    authVerifyCallback->onVerifyFailed(REQUEST_ID, SOFTBUS_OK);
    authVerifyCallback->onVerifyFailed(REQUEST_ID, HICHAIN_ERROR_KEY_NOEXIST);
}

/*
 * @tc.name: LNN_NOTIFY_AUTH_HANDLE_LEAVELNN_TEST_001
 * @tc.desc: lnn notify auth handle leave lnn test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(LNNNetBuilderTest, LNN_NOTIFY_AUTH_HANDLE_LEAVELNN_TEST_001, TestSize.Level0)
{
    AuthHandle authHandle = { .authId = AUTH_ID, .type = AUTH_LINK_TYPE_WIFI };
    int32_t ret = LnnNotifyAuthHandleLeaveLNN(authHandle);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = LnnInitNetBuilder();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnNotifyAuthHandleLeaveLNN(authHandle);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}
} // namespace OHOS
