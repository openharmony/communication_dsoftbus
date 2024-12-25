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

#include "auth_interface.h"
#include "lnn_net_builder.c"
#include "lnn_net_builder_mock.h"
#include "lnn_net_ledger_mock.h"
#include "lnn_service_mock.h"
#include "lnn_sync_info_manager.c"
#include "lnn_sync_info_manager.h"
#include "lnn_sync_info_manager_mock.h"
#include "lnn_trans_mock.h"
#include "message_handler.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

constexpr char NETWORKID[65] = "abcdefg";
constexpr char NODE_NETWORK_ID[65] = "gfedcba";
constexpr uint8_t MSG[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9 };
constexpr char MSG_DATA[] = { '0', '1', '2', '3', '4', '5', '6', '7', '8', '9' };
constexpr char MSG_DATA1[] = { -1 };
constexpr char MSG_DATA2[] = { 1 };
constexpr uint32_t LEN = 10;
constexpr uint32_t LENGTH = 8192;
constexpr char MSG_TEST[] = "msg";
class LNNSyncInfoManagerTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void LNNSyncInfoManagerTest::SetUpTestCase() { }

void LNNSyncInfoManagerTest::TearDownTestCase() { }

void LNNSyncInfoManagerTest::SetUp() { }

void LNNSyncInfoManagerTest::TearDown() { }

void Handler(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len) { }

void Complete(LnnSyncInfoType type, const char *networkId, const uint8_t *msg, uint32_t len) { }

/*
 * @tc.name: LNN_INIT_SYNC_INFO_MANAGER_TEST_001
 * @tc.desc: LnnInitSyncInfoManager
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_INIT_SYNC_INFO_MANAGER_TEST_001, TestSize.Level1)
{
    LooperInit();
    NiceMock<LnnTransInterfaceMock> transMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(transMock, TransRegisterNetworkingChannelListener)
        .WillRepeatedly(DoAll(LnnTransInterfaceMock::ActionOfTransRegister, Return(SOFTBUS_OK)));
    int32_t ret = LnnInitSyncInfoManager();
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_REG_SYNC_INFO_HANDLER_TEST_001
 * @tc.desc: invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_REG_SYNC_INFO_HANDLER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_COUNT, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_UNREG_SYNC_INFO_HANDLER_TEST_001
 * @tc.desc: invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_UNREG_SYNC_INFO_HANDLER_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_COUNT, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_OFFLINE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    LnnRegSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    ret = LnnUnregSyncInfoHandler(LNN_INFO_TYPE_TOPO_UPDATE, Handler);
    EXPECT_TRUE(ret == SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_SYNC_INFO_MSG_TEST_001
 * @tc.desc: invalid parameter
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_SYNC_INFO_MSG_TEST_001, TestSize.Level1)
{
    int32_t ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_COUNT, NETWORKID, MSG, LEN, Complete);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = LnnSendSyncInfoMsg(LNN_INFO_TYPE_ROUTE_LSU, NETWORKID, MSG, LENGTH, Complete);
    EXPECT_TRUE(ret == SOFTBUS_MEM_ERR);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_001
 * @tc.desc: LnnSendP2pSyncInfoMsg test
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_001, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillRepeatedly(Return(msg));

    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_EQ(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_002
 * @tc.desc: networkId == NULL
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_002, TestSize.Level1)
{
    NiceMock<LnnServicetInterfaceMock> serviceMock;
    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    uint32_t netCapability = 0;
    int32_t ret = LnnSendP2pSyncInfoMsg(nullptr, netCapability);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_003
 * @tc.desc: GetAuthHandleByNetworkId(networkId, &authHandle) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(2)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = AUTH_INVALID_ID, .type = 1 }), Return(SOFTBUS_ERR)))
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = AUTH_INVALID_ID, .type = 1 }), Return(SOFTBUS_ERR)));

    EXPECT_NE(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_004
 * @tc.desc: AuthGetLatestAuthSeqListByType != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_004, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_ERR)));

    EXPECT_NE(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_005
 * @tc.desc: msg == NULL
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_005, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(nullptr));

    EXPECT_NE(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_006
 * @tc.desc: SoftBusGenerateRandomArray((uint8_t *)&dataInfo.seq, sizeof(int64_t)) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_006, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillRepeatedly(Return(msg));

    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_NE(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_007
 * @tc.desc: AuthPostTransData(authHandle, &dataInfo) == SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_007, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillRepeatedly(Return(msg));

    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: LNN_SEND_P2P_SYNC_INFO_MSG_TEST_008
 * @tc.desc: AuthPostTransData(authHandle, &dataInfo) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: I5OMIK
 */
HWTEST_F(LNNSyncInfoManagerTest, LNN_SEND_P2P_SYNC_INFO_MSG_TEST_008, TestSize.Level1)
{
    int64_t newLocalAuthSeq[2] = { 1, 2 };
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> serviceMock;

    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(2).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillRepeatedly(Return(msg));

    EXPECT_CALL(serviceMock, SoftBusGenerateRandomArray).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    EXPECT_EQ(LnnSendP2pSyncInfoMsg(NETWORKID, 0), SOFTBUS_OK);
}

/*
 * @tc.name: FindSyncChannelInfoByChannelId_001
 * @tc.desc: return NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, FindSyncChannelInfoByChannelId_001, TestSize.Level1)
{
    ClearSyncChannelInfo();
    EXPECT_EQ(FindSyncChannelInfoByChannelId(10), NULL);
}

/*
 * @tc.name: SendSyncInfoMsg_001
 * @tc.desc: SendSyncInfoMsgOnly
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, SendSyncInfoMsg_001, TestSize.Level1)
{
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }

    info->clientChannelId = 10;
    SoftBusSysTime sysTime;
    info->accessTime = sysTime;
    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info sync error!");
        return;
    }

    NiceMock<LnnTransInterfaceMock> transMock;
    EXPECT_CALL(transMock, TransSendNetworkingMessage(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    SendSyncInfoMsg(info, msg);
}

/*
 * @tc.name: DumpMsgExcludeListNode_001
 * @tc.desc: return newMsg;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, DumpMsgExcludeListNode_001, TestSize.Level1)
{
    EXPECT_EQ(DumpMsgExcludeListNode(nullptr), nullptr);

    SyncInfoMsg *newItem = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (newItem == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info sync error!");
        return;
    }
    EXPECT_NE(DumpMsgExcludeListNode(newItem), nullptr);

    SoftBusFree(newItem);
}

/*
 * @tc.name: DumpSyncInfoMsgList_001
 * @tc.desc: return SOFTBUS_OK;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, DumpSyncInfoMsgList_001, TestSize.Level1)
{
    EXPECT_EQ(DumpSyncInfoMsgList(nullptr, nullptr), SOFTBUS_INVALID_PARAM);

    SyncChannelInfo *newInfo = CreateSyncChannelInfo(NETWORKID);
    if (newInfo == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }

    EXPECT_EQ(DumpSyncInfoMsgList(&info->syncMsgList, &newInfo->syncMsgList), SOFTBUS_OK);

    SoftBusFree(info);
    SoftBusFree(newInfo);
}

/*
 * @tc.name: DumpSyncChannelInfo_001
 * @tc.desc: return newInfo;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, DumpSyncChannelInfo_001, TestSize.Level1)
{
    SoftBusSysTime now;
    SoftBusGetTime(&now);
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    info->serverChannelId = 10;
    info->accessTime = now;
    info->isClientOpened = 0;
    DestroySyncInfoMsgList(&info->syncMsgList);

    EXPECT_NE(DumpSyncChannelInfo(info), nullptr);
    SoftBusFree(info);
}

/*
 * @tc.name: SendSyncInfoMsgFromList_001
 * @tc.desc: SendSyncInfoMsgFromList
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, SendSyncInfoMsgFromList_001, TestSize.Level1)
{
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    SyncInfoMsg *newItem = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (newItem == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info sync error!");
        return;
    }

    ListTailInsert(&info->syncMsgList, &newItem->node);

    NiceMock<LnnTransInterfaceMock> transMock;
    EXPECT_CALL(transMock, TransSendNetworkingMessage(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    SendSyncInfoMsgFromList(info);
    SoftBusFree(info);
}

/*
 * @tc.name: ResetOpenChannelInfo_001
 * @tc.desc: info->serverChannelId != channelId && info->serverChannelId != INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, ResetOpenChannelInfo_001, TestSize.Level1)
{
    int32_t *oldChannelId = new int32_t(0);
    int32_t channelId = 10;
    unsigned char isServer = true;
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = 1;
    ResetOpenChannelInfo(channelId, isServer, info, oldChannelId);

    EXPECT_EQ(info->serverChannelId, channelId);
    delete (oldChannelId);
    oldChannelId = nullptr;
    SoftBusFree(info);
}

/*
 * @tc.name: ResetOpenChannelInfo_002
 * @tc.desc: info->serverChannelId != channelId && info->serverChannelId != INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, ResetOpenChannelInfo_002, TestSize.Level1)
{
    int32_t *oldChannelId = new int32_t(0);
    int32_t channelId = 10;
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 1;
    ResetOpenChannelInfo(channelId, false, info, oldChannelId);

    EXPECT_EQ(info->clientChannelId, channelId);
    delete (oldChannelId);
    oldChannelId = nullptr;
    SoftBusFree(info);
}

/*
 * @tc.name: AddChannelInfoNode_001
 * @tc.desc: isServer = false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, AddChannelInfoNode_001, TestSize.Level1)
{
    int32_t channelId = 10;
    unsigned char isServer = false;
    EXPECT_EQ(AddChannelInfoNode(NETWORKID, channelId, isServer), SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: OnChannelOpened_001
 * @tc.desc: LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpened_001, TestSize.Level1)
{
    int32_t channelId = 10;
    unsigned char isServer = false;

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(OnChannelOpened(channelId, nullptr, isServer), SOFTBUS_ERR);
}

/*
 * @tc.name: OnChannelOpened_002
 * @tc.desc: !isServer == true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpened_002, TestSize.Level1)
{
    int32_t channelId = 10;
    unsigned char isServer = true;
    const char *peerUuid = nullptr;
    ClearSyncChannelInfo();
    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = channelId;
    info->clientChannelId = channelId;
    ListTailInsert(&info->syncMsgList, &msg->node);
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    NiceMock<LnnTransInterfaceMock> lnnTransMock;
    EXPECT_CALL(lnnTransMock, TransSendNetworkingMessage(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    NiceMock<LnnNetLedgertInterfaceMock> lnnNetLedgertMock;
    EXPECT_CALL(lnnNetLedgertMock, LnnConvertDlId(_, _, _, _, _))
        .WillRepeatedly(DoAll(SetArrayArgument<3>(NETWORKID, NETWORKID + LEN), Return(SOFTBUS_OK)));
    EXPECT_EQ(OnChannelOpened(channelId, peerUuid, isServer), SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelOpened_003
 * @tc.desc: oldChannelId != INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpened_003, TestSize.Level1)
{
    int32_t channelId = 10;
    unsigned char isServer = true;
    const char *peerUuid = nullptr;
    ClearSyncChannelInfo();

    SyncChannelInfo *info = CreateSyncChannelInfo(NODE_NETWORK_ID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = 100;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    NiceMock<LnnNetLedgertInterfaceMock> lnnNetLedgerMock;
    NiceMock<LnnTransInterfaceMock> lnnTransMock;
    EXPECT_CALL(lnnNetLedgerMock, LnnConvertDlId(_, _, _, _, _))
        .WillRepeatedly(DoAll(SetArrayArgument<3>(NETWORKID, NETWORKID + LEN), Return(SOFTBUS_OK)));
    EXPECT_EQ(OnChannelOpened(channelId, peerUuid, isServer), SOFTBUS_OK);
}

/*
 * @tc.name: OnChannelCloseCommon_001
 * @tc.desc: info->serverChannelId == channelId
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelCloseCommon_001, TestSize.Level1)
{
    int32_t channelId = 10;
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = channelId;

    OnChannelCloseCommon(info, channelId);
    EXPECT_EQ(info->serverChannelId, INVALID_CHANNEL_ID);
    SoftBusFree(info);
}

/*
 * @tc.name: OnChannelCloseCommon_002
 * @tc.desc: oldChannelId != INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelCloseCommon_002, TestSize.Level1)
{
    int32_t channelId = 10;
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = 1;

    OnChannelCloseCommon(info, channelId);
    EXPECT_EQ(info->clientChannelId, INVALID_CHANNEL_ID);
    SoftBusFree(info);
}

/*
 * @tc.name: OnChannelCloseCommon_003
 * @tc.desc: info->serverChannelId == INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelCloseCommon_003, TestSize.Level1)
{
    int32_t channelId = 10;
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = INVALID_CHANNEL_ID;

    OnChannelCloseCommon(info, channelId);
}

/*
 * @tc.name: OnChannelOpenFailed_001
 * @tc.desc: LnnConvertDlId(peerUuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpenFailed_001, TestSize.Level1)
{
    int32_t channelId = 10;
    const char *peerUuid = nullptr;
    NiceMock<LnnNetLedgertInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    OnChannelOpenFailed(channelId, peerUuid);
}

/*
 * @tc.name: OnChannelOpenFailed_002
 * @tc.desc: info == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpenFailed_002, TestSize.Level1)
{
    int32_t channelId = 10;
    const char *peerUuid = nullptr;

    auto mockHandler = [](const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf,
                           uint32_t dstIdBufLen) {
        memcpy_s(dstIdBuf, NETWORK_ID_BUF_LEN, "abc", sizeof("abc"));
        return SOFTBUS_OK;
    };

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).Times(1).WillOnce(Invoke(mockHandler));

    ClearSyncChannelInfo();

    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 1;
    ListTailInsert(&info->syncMsgList, &msg->node);
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    OnChannelOpenFailed(channelId, peerUuid);
    ClearSyncChannelInfo();
}

/*
 * @tc.name: OnChannelOpenFailed_003
 * @tc.desc: SUCCESS
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelOpenFailed_003, TestSize.Level1)
{
    int32_t channelId = 10;
    const char *peerUuid = nullptr;

    auto mockHandler = [](const char *srcId, IdCategory srcIdType, IdCategory dstIdType, char *dstIdBuf,
                           uint32_t dstIdBufLen) {
        memcpy_s(dstIdBuf, NETWORK_ID_BUF_LEN, "0123456789", sizeof("0123456789"));
        return SOFTBUS_OK;
    };

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).Times(1).WillOnce(Invoke(mockHandler));

    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 1;
    info->serverChannelId = channelId;

    ListTailInsert(&info->syncMsgList, &msg->node);
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    OnChannelOpenFailed(channelId, peerUuid);
    ClearSyncChannelInfo();
}

/*
 * @tc.name: OnChannelClosed_001
 * @tc.desc: info == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelClosed_001, TestSize.Level1)
{
    int32_t channelId = 10;
    ClearSyncChannelInfo();

    OnChannelClosed(channelId);
}

/*
 * @tc.name: OnChannelClosed_002
 * @tc.desc: info == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnChannelClosed_002, TestSize.Level1)
{
    int32_t channelId = 10;

    ClearSyncChannelInfo();
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    OnChannelClosed(channelId);
}

/*
 * @tc.name: OnMessageReceived_001
 * @tc.desc: len <= MSG_HEAD_LEN   &   len <= MSG_HEAD_LEN   &   info == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnMessageReceived_001, TestSize.Level1)
{
    int32_t channelId = 10;
    uint32_t len = 10;
    OnMessageReceived(channelId, nullptr, len);

    len = 1;
    OnMessageReceived(channelId, MSG_DATA, len);

    len = 10;
    ListDelete(&g_syncInfoManager.channelInfoList);
    OnMessageReceived(channelId, MSG_DATA, len);
}

/*
 * @tc.name: OnMessageReceived_002
 * @tc.desc: type < 0 || type >= LNN_INFO_TYPE_COUNT
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnMessageReceived_002, TestSize.Level1)
{
    int32_t channelId = 10;
    uint32_t len = 10;

    ListDelete(&g_syncInfoManager.channelInfoList);
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    OnMessageReceived(channelId, MSG_DATA1, len);
    SoftBusFree(info);
}

/*
 * @tc.name: OnMessageReceived_003
 * @tc.desc: handler == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnMessageReceived_003, TestSize.Level1)
{
    int32_t channelId = 10;
    uint32_t len = 10;

    ListDelete(&g_syncInfoManager.channelInfoList);
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);
    g_syncInfoManager.handlers[1] = nullptr;

    OnMessageReceived(channelId, MSG_DATA2, len);
    SoftBusFree(info);
}

/*
 * @tc.name: PackBleOfflineMsg_001
 * @tc.desc: json == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackBleOfflineMsg_001, TestSize.Level1)
{
    int64_t connCap = 0;
    int32_t networkType = 0;
    int64_t authSeq = 0;

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(nullptr));

    EXPECT_EQ(PackBleOfflineMsg(connCap, networkType, authSeq), nullptr);
}

/*
 * @tc.name: PackBleOfflineMsg_002
 * @tc.desc: !JSON_AddInt64ToObject(json, NETWORK_SYNC_CONN_CAP, connCap)
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackBleOfflineMsg_002, TestSize.Level1)
{
    int64_t connCap = 0;
    int32_t networkType = 0;
    int64_t authSeq = 0;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(false));

    EXPECT_EQ(PackBleOfflineMsg(connCap, networkType, authSeq), nullptr);
}

/*
 * @tc.name: PackBleOfflineMsg_003
 * @tc.desc: SUCCESS
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackBleOfflineMsg_003, TestSize.Level1)
{
    int64_t connCap = 0;
    int32_t networkType = 0;
    int64_t authSeq = 0;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_AddInt64ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_PrintUnformatted(_)).Times(1).WillRepeatedly(Return(nullptr));

    EXPECT_EQ(PackBleOfflineMsg(connCap, networkType, authSeq), nullptr);
}

/*
 * @tc.name: PackWifiOfflineMsg_001
 * @tc.desc: json == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackWifiOfflineMsg_001, TestSize.Level1)
{
    int64_t authPort = 0;
    char offlineCode[] = { 0 };

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(nullptr));

    EXPECT_EQ(PackWifiOfflineMsg(authPort, offlineCode), nullptr);
}

/*
 * @tc.name: PackWifiOfflineMsg_002
 * @tc.desc: !JSON_AddInt64ToObject(json, NETWORK_SYNC_CONN_CAP, connCap)
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackWifiOfflineMsg_002, TestSize.Level1)
{
    int64_t authPort = 0;
    char offlineCode[] = { 0 };

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(mock, JSON_AddStringToObject(_, _, _)).WillRepeatedly(Return(false));

    EXPECT_EQ(PackWifiOfflineMsg(authPort, offlineCode), nullptr);
}

/*
 * @tc.name: PackWifiOfflineMsg_003
 * @tc.desc: SUCCESS
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, PackWifiOfflineMsg_003, TestSize.Level1)
{
    int64_t authPort = 0;
    char offlineCode[] = { 0 };

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_CreateObject()).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_AddStringToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_PrintUnformatted(_)).Times(1).WillOnce(Return(nullptr));

    EXPECT_EQ(PackWifiOfflineMsg(authPort, offlineCode), nullptr);
}

/*
 * @tc.name: CheckPeerAuthSeq_001
 * @tc.desc: LnnConvertDlId(uuid, CATEGORY_UUID, CATEGORY_UDID, udid, UDID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckPeerAuthSeq_001, TestSize.Level1)
{
    const char *uuid = nullptr;
    int64_t peerAuthSeq = 0;

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(CheckPeerAuthSeq(uuid, peerAuthSeq), SOFTBUS_ERR);
}

/*
 * @tc.name: CheckPeerAuthSeq_002
 * @tc.desc: AuthGetLatestAuthSeqListByType(udid, localAuthSeq, authVerifyTime, DISCOVERY_TYPE_BLE) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckPeerAuthSeq_002, TestSize.Level1)
{
    const char *uuid = nullptr;
    int64_t peerAuthSeq = 0;

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(CheckPeerAuthSeq(uuid, peerAuthSeq), SOFTBUS_ERR);
}

/*
 * @tc.name: CheckPeerAuthSeq_003
 * @tc.desc: peerAuthSeq == 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckPeerAuthSeq_003, TestSize.Level1)
{
    const char *uuid = nullptr;
    int64_t peerAuthSeq = 0;

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_NE(CheckPeerAuthSeq(uuid, peerAuthSeq), SOFTBUS_OK);
}

/*
 * @tc.name: CheckPeerAuthSeq_004
 * @tc.desc: return SOFTBUS_OK;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckPeerAuthSeq_004, TestSize.Level1)
{
    const char *uuid = nullptr;
    int64_t peerAuthSeq = 10;
    int64_t newLocalAuthSeq[2] = { 10, 2 };

    NiceMock<LnnNetLedgertInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    EXPECT_EQ(CheckPeerAuthSeq(uuid, peerAuthSeq), SOFTBUS_OK);
}

/*
 * @tc.name: BleOffLineProcess_001
 * @tc.desc: return SOFTBUS_OK;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, BleOffLineProcess_001, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(nullptr));

    BleOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: BleOffLineProcess_002
 * @tc.desc: !JSON_GetInt64FromOject(json, NETWORK_SYNC_CONN_CAP, &peerConnCap) == true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, BleOffLineProcess_002, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt64FromOject(_, _, _)).WillRepeatedly(Return(false));

    BleOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: BleOffLineProcess_003
 * @tc.desc: LnnHasCapability((uint32_t)peerConnCap, BIT_BLE) == true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, BleOffLineProcess_003, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt64FromOject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnHasCapability(_, _)).WillRepeatedly(Return(true));

    BleOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: BleOffLineProcess_004
 * @tc.desc: AuthGetDeviceUuid(authHandle.authId, uuid, UUID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, BleOffLineProcess_004, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;

    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt64FromOject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(ledgerMock, LnnHasCapability(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnServerMock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    BleOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: BleOffLineProcess_005
 * @tc.desc: LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_BLE) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, BleOffLineProcess_005, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;
    int64_t newLocalAuthSeq[2] = { 1, 2 };

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;

    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt64FromOject(_, _, _))
        .WillOnce(Return(true))
        .WillOnce(DoAll(SetArgPointee<2>(10), Return(true)));
    EXPECT_CALL(ledgerMock, LnnHasCapability(_, _)).WillRepeatedly(Return(false));
    EXPECT_CALL(lnnServerMock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, AuthGetLatestAuthSeqListByType)
        .WillOnce(DoAll(SetArrayArgument<1>(newLocalAuthSeq, newLocalAuthSeq + 2), Return(SOFTBUS_OK)));

    BleOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: CheckWifiOfflineMsgResult_001
 * @tc.desc: LnnGetRemoteNumInfo(networkId, NUM_KEY_AUTH_PORT, &port) != 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckWifiOfflineMsgResult_001, TestSize.Level1)
{
    int32_t authPort = 0;
    const char *offlineCode = nullptr;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(CheckWifiOfflineMsgResult(NETWORKID, authPort, offlineCode), false);
}

/*
 * @tc.name: CheckWifiOfflineMsgResult_002
 * @tc.desc: LnnGetNodeKeyInfo(networkId, NODE_KEY_BLE_OFFLINE_CODE, remoteOfflineCode, WIFI_OFFLINE_CODE_LEN) != 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckWifiOfflineMsgResult_002, TestSize.Level1)
{
    int32_t authPort = 0;
    const char *offlineCode = nullptr;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetNodeKeyInfo(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(CheckWifiOfflineMsgResult(NETWORKID, authPort, offlineCode), false);
}

/*
 * @tc.name: CheckWifiOfflineMsgResult_003
 * @tc.desc: ConvertBytesToHexString != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckWifiOfflineMsgResult_003, TestSize.Level1)
{
    int32_t authPort = 0;
    const char *offlineCode = nullptr;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;

    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _)).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetNodeKeyInfo(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(CheckWifiOfflineMsgResult(NETWORKID, authPort, offlineCode), false);
}

/*
 * @tc.name: CheckWifiOfflineMsgResult_004
 * @tc.desc: strcmp(convertOfflineCode, offlineCode) != 0 || port != authPort
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckWifiOfflineMsgResult_004, TestSize.Level1)
{
    int32_t authPort = 0;
    int32_t newAuthPort = 10;
    char offlineCode[] = "123";

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;

    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(newAuthPort), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetNodeKeyInfo(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_EQ(CheckWifiOfflineMsgResult(NETWORKID, authPort, offlineCode), false);
}

/*
 * @tc.name: CheckWifiOfflineMsgResult_005
 * @tc.desc: return true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, CheckWifiOfflineMsgResult_005, TestSize.Level1)
{
    int32_t authPort = 0;
    int32_t newAuthPort = 0;
    char offlineCode[] = "123";

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;

    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(newAuthPort), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetNodeKeyInfo(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _))
        .WillOnce(DoAll(SetArrayArgument<0>(offlineCode, offlineCode + 3), Return(SOFTBUS_OK)));

    EXPECT_EQ(CheckWifiOfflineMsgResult(NETWORKID, authPort, offlineCode), true);
}

/*
 * @tc.name: WlanOffLineProcess_001
 * @tc.desc: json == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, WlanOffLineProcess_001, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(nullptr));

    WlanOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: WlanOffLineProcess_002
 * @tc.desc: !JSON_GetInt32FromOject(json, NETWORK_OFFLINE_PORT, &authPort) == false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, WlanOffLineProcess_002, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillRepeatedly(Return(false));

    WlanOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: WlanOffLineProcess_003
 * @tc.desc: AuthGetDeviceUuid(authHandle.authId, uuid, UUID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, WlanOffLineProcess_003, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_GetStringFromOject(_, _, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnServerMock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    WlanOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: WlanOffLineProcess_004
 * @tc.desc: LnnConvertDlId(uuid, CATEGORY_UUID, CATEGORY_NETWORK_ID, networkId, NETWORK_ID_BUF_LEN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, WlanOffLineProcess_004, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;
    NiceMock<LnnNetLedgertInterfaceMock> lnnNetLedgertmock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(mock, JSON_GetStringFromOject(_, _, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnServerMock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnNetLedgertmock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    WlanOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: WlanOffLineProcess_005
 * @tc.desc: CheckWifiOfflineMsgResult(networkId, authPort, convertOfflineCode) == true &&
 *           LnnRequestLeaveSpecific(networkId, CONNECTION_ADDR_WLAN) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, WlanOffLineProcess_005, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    AuthHandle authHandle;
    int32_t newAuthPort = 12345;
    char offlineCode[] = "123";

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillOnce(DoAll(SetArgPointee<2>(newAuthPort), Return(true)));
    EXPECT_CALL(mock, JSON_GetStringFromOject(_, _, _, _))
        .WillOnce(DoAll(SetArrayArgument<2>(offlineCode, offlineCode + 3), Return(true)));
    EXPECT_CALL(lnnServerMock, AuthGetDeviceUuid(_, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNumInfo(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(newAuthPort), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetNodeKeyInfo(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, ConvertBytesToHexString(_, _, _, _))
        .WillOnce(DoAll(SetArrayArgument<0>(offlineCode, offlineCode + 3), Return(SOFTBUS_OK)));

    WlanOffLineProcess(&data, authHandle);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_001
 * @tc.desc: data == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_001, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = 0;
    AuthHandle authHandle;

    OnP2pNetworkingDataRecv(authHandle, &data);
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_002
 * @tc.desc: data->module != MODULE_P2P_NETWORKING_SYNC
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_002, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = LEN;
    data.module = ConnModule::MODULE_TRUST_ENGINE;
    AuthHandle authHandle;

    OnP2pNetworkingDataRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_003
 * @tc.desc: json == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_003, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = LEN;
    data.module = ConnModule::MODULE_P2P_NETWORKING_SYNC;
    AuthHandle authHandle;

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(nullptr));

    OnP2pNetworkingDataRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_004
 * @tc.desc: JSON_GetInt32FromOject(json, NETWORK_SYNC_TYPE, &peerNetworkType) == false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_004, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = LEN;
    data.module = ConnModule::MODULE_P2P_NETWORKING_SYNC;
    AuthHandle authHandle;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillRepeatedly(Return(&json));
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillRepeatedly(Return(false));

    OnP2pNetworkingDataRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_005
 * @tc.desc: peerNetworkType == DISCOVERY_TYPE_BLE
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_005, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = LEN;
    data.module = ConnModule::MODULE_P2P_NETWORKING_SYNC;
    AuthHandle authHandle;
    int32_t peerNetworkType = DISCOVERY_TYPE_BLE;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillOnce(Return(&json)).WillOnce(nullptr);
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillOnce(DoAll(SetArgPointee<2>(peerNetworkType), Return(true)));

    OnP2pNetworkingDataRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnP2pNetworkingDataRecv_006
 * @tc.desc: peerNetworkType == DISCOVERY_TYPE_WIFI
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnP2pNetworkingDataRecv_006, TestSize.Level1)
{
    AuthTransData data;
    data.data = new uint8_t(0);
    data.len = LEN;
    data.module = ConnModule::MODULE_P2P_NETWORKING_SYNC;
    AuthHandle authHandle;
    int32_t peerNetworkType = DISCOVERY_TYPE_WIFI;

    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, JSON_Parse(_, _)).WillOnce(Return(&json)).WillOnce(nullptr);
    EXPECT_CALL(mock, JSON_GetInt32FromOject(_, _, _)).WillOnce(DoAll(SetArgPointee<2>(peerNetworkType), Return(true)));

    OnP2pNetworkingDataRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: LnnSyncManagerHandleOffline_001
 * @tc.desc: item == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSyncManagerHandleOffline_001, TestSize.Level1)
{
    ListDelete(&g_syncInfoManager.channelInfoList);

    LnnSyncManagerHandleOffline(NETWORKID);
}

/*
 * @tc.name: LnnSyncManagerHandleOffline_002
 * @tc.desc: item->clientChannelId != INVALID_CHANNEL_ID && item->serverChannelId != INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSyncManagerHandleOffline_002, TestSize.Level1)
{
    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->clientChannelId = 10;
    info->serverChannelId = 10;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    NiceMock<LnnTransInterfaceMock> mock;
    EXPECT_CALL(mock, TransCloseNetWorkingChannel(_)).Times(2);

    LnnSyncManagerHandleOffline(NETWORKID);
}

/*
 * @tc.name: OnLnnOnlineStateChange_001
 * @tc.desc: info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnLnnOnlineStateChange_001, TestSize.Level1)
{
    LnnEventBasicInfo info;
    info.event = LNN_EVENT_IP_ADDR_CHANGED;

    OnLnnOnlineStateChange(&info);

    info.event = LNN_EVENT_NODE_ONLINE_STATE_CHANGED;
    OnLnnOnlineStateChange(&info);
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_001
 * @tc.desc: data == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_001, TestSize.Level1)
{
    AuthTransData *data = nullptr;
    AuthHandle authHandle;
    OnWifiDirectSyncMsgRecv(authHandle, data);
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_002
 * @tc.desc: data->len <= MSG_HEAD_LEN
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_002, TestSize.Level1)
{
    AuthTransData data;
    data.len = 0;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    OnWifiDirectSyncMsgRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_003
 * @tc.desc: auth == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_003, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(0);
    AuthHandle authHandle;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(nullptr));

    OnWifiDirectSyncMsgRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_004
 * @tc.desc: LnnGetNetworkIdByUdid(auth->udid, networkId, sizeof(networkId)) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_004, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(0);
    AuthHandle authHandle;
    AuthManager authManager;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(&authManager));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetNetworkIdByUdid(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_CALL(lnnSyncInfoMgrMock, DelAuthManager(_, _)).Times(1);

    OnWifiDirectSyncMsgRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_005
 * @tc.desc: type < 0 || type >= LNN_INFO_TYPE_COUNT
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_005, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(0);
    AuthHandle authHandle;
    AuthManager authManager;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(&authManager));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetNetworkIdByUdid(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, DelAuthManager(_, _)).Times(1);

    OnWifiDirectSyncMsgRecv(authHandle, &data);
    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_006
 * @tc.desc: handler == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_006, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(10);
    AuthHandle authHandle;
    AuthManager authManager;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(&authManager));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetNetworkIdByUdid(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, DelAuthManager(_, _)).Times(1);

    OnWifiDirectSyncMsgRecv(authHandle, &data);

    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_007
 * @tc.desc: handler == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_007, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(LNN_INFO_TYPE_NICK_NAME);
    AuthHandle authHandle;
    AuthManager authManager;
    g_syncInfoManager.handlers[LNN_INFO_TYPE_NICK_NAME] = nullptr;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(&authManager));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetNetworkIdByUdid(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, DelAuthManager(_, _)).Times(1);

    OnWifiDirectSyncMsgRecv(authHandle, &data);

    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncMsgRecv_008
 * @tc.desc: SUCCESS
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncMsgRecv_008, TestSize.Level1)
{
    AuthTransData data;
    data.len = 10;
    data.data = new uint8_t(LNN_INFO_TYPE_NICK_NAME);
    AuthHandle authHandle;
    AuthManager authManager;
    g_syncInfoManager.handlers[LNN_INFO_TYPE_NICK_NAME] = Complete;

    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(lnnSyncInfoMgrMock, GetAuthManagerByAuthId(_)).Times(1).WillOnce(Return(&authManager));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetNetworkIdByUdid(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, DelAuthManager(_, _)).Times(1);

    OnWifiDirectSyncMsgRecv(authHandle, &data);

    delete (data.data);
    data.data = nullptr;
}

/*
 * @tc.name: OnWifiDirectSyncAuthClose_001
 * @tc.desc: SUCCESS
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, OnWifiDirectSyncAuthClose_001, TestSize.Level1)
{
    AuthHandle authHandle;
    OnWifiDirectSyncAuthClose(authHandle);
}

/*
 * @tc.name: ResetSendSyncInfo_001
 * @tc.desc: oldInfo->clientChannelId == INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, ResetSendSyncInfo_001, TestSize.Level1)
{
    SoftBusSysTime time = {
        .sec = 0,
        .usec = 0,
    };

    SyncChannelInfo oldInfo = {
        .clientChannelId = INVALID_CHANNEL_ID,
    };

    SyncChannelInfo newInfo = {
        .clientChannelId = 10,
        .accessTime = time,
    };

    SyncInfoMsg msg;

    ResetSendSyncInfo(&oldInfo, &newInfo, &msg);
    EXPECT_EQ(oldInfo.clientChannelId, newInfo.clientChannelId);
    EXPECT_EQ(oldInfo.accessTime.sec, newInfo.accessTime.sec);
    EXPECT_EQ(oldInfo.accessTime.usec, newInfo.accessTime.usec);
}

/*
 * @tc.name: ResetSendSyncInfo_002
 * @tc.desc: oldInfo->isClientOpened = false
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, ResetSendSyncInfo_002, TestSize.Level1)
{
    SoftBusSysTime time = {
        .sec = 0,
        .usec = 0,
    };

    SyncChannelInfo oldInfo = {
        .clientChannelId = 100,
        .isClientOpened = true,
    };

    SyncChannelInfo newInfo = {
        .clientChannelId = 10,
        .accessTime = time,
    };

    SyncInfoMsg msg;

    NiceMock<LnnTransInterfaceMock> mock;
    EXPECT_CALL(mock, TransCloseNetWorkingChannel(_)).Times(1);

    ResetSendSyncInfo(&oldInfo, &newInfo, &msg);

    EXPECT_EQ(oldInfo.isClientOpened, false);
    EXPECT_EQ(oldInfo.clientChannelId, newInfo.clientChannelId);
}

/*
 * @tc.name: ResetSendSyncInfo_003
 * @tc.desc: oldInfo->isClientOpened = true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, ResetSendSyncInfo_003, TestSize.Level1)
{
    SoftBusSysTime time = {
        .sec = 0,
        .usec = 0,
    };

    SyncChannelInfo oldInfo = {
        .clientChannelId = 100,
        .isClientOpened = false,
        .accessTime = time,
    };

    SyncChannelInfo newInfo = {
        .clientChannelId = 100,
        .accessTime = time,
    };

    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    NiceMock<LnnTransInterfaceMock> mock;
    EXPECT_CALL(mock, TransSendNetworkingMessage(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    ResetSendSyncInfo(&oldInfo, &newInfo, msg);
}

/*
 * @tc.name: SendSyncInfoByNewChannel_001
 * @tc.desc: info->clientChannelId == INVALID_CHANNEL_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, SendSyncInfoByNewChannel_001, TestSize.Level1)
{
    SyncInfoMsg msg;
    NiceMock<LnnTransInterfaceMock> transMock;
    EXPECT_CALL(transMock, TransOpenNetWorkingChannel(_, _)).Times(1).WillOnce(Return(INVALID_CHANNEL_ID));

    SendSyncInfoByNewChannel(NETWORKID, &msg);
}

/*
 * @tc.name: SendSyncInfoByNewChannel_002
 * @tc.desc: IsListEmpty(&g_syncInfoManager.channelInfoList)
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, SendSyncInfoByNewChannel_002, TestSize.Level1)
{
    SyncInfoMsg msg;
    int32_t id = 10;
    ListDelete(&g_syncInfoManager.channelInfoList);
    NiceMock<LnnTransInterfaceMock> transMock;
    NiceMock<LnnServicetInterfaceMock> lnnServerMock;

    EXPECT_CALL(transMock, TransOpenNetWorkingChannel(_, _)).Times(1).WillOnce(Return(id));
    EXPECT_CALL(lnnServerMock, LnnAsyncCallbackDelayHelper(_, _, _, _)).Times(1);

    SendSyncInfoByNewChannel(NETWORKID, &msg);
}

/*
 * @tc.name: TrySendSyncInfoMsg_001
 * @tc.desc: info->isClientOpened == true
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, TrySendSyncInfoMsg_001, TestSize.Level1)
{
    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    int32_t id = 10;
    ListDelete(&g_syncInfoManager.channelInfoList);

    SyncChannelInfo *info = CreateSyncChannelInfo(NETWORKID);
    if (info == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync channel info error!");
        return;
    }
    info->serverChannelId = id;
    info->clientChannelId = id;
    info->isClientOpened = true;
    ListNodeInsert(&g_syncInfoManager.channelInfoList, &info->node);

    NiceMock<LnnTransInterfaceMock> transMock;
    EXPECT_CALL(transMock, TransSendNetworkingMessage(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_ERR));

    EXPECT_EQ(TrySendSyncInfoMsg(NODE_NETWORK_ID, msg), SOFTBUS_OK);
}

/*
 * @tc.name: GetWifiDirectAuthByNetworkId_001
 * @tc.desc: authHandle->authId != AUTH_INVALID_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetWifiDirectAuthByNetworkId_001, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = 10,
    };

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1);
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAuthHandle);

    EXPECT_EQ(GetWifiDirectAuthByNetworkId(NETWORKID, &authHandle), SOFTBUS_OK);
}

/*
 * @tc.name: GetWifiDirectAuthByNetworkId_002
 * @tc.desc: return SOFTBUS_ERR;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetWifiDirectAuthByNetworkId_002, TestSize.Level1)
{
    AuthHandle authHandle = {
        .authId = AUTH_INVALID_ID,
    };

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1);
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid)
        .WillRepeatedly(LnnNetLedgertInterfaceMock::ActionOfLnnGetAuthHandle);

    EXPECT_EQ(GetWifiDirectAuthByNetworkId(NETWORKID, &authHandle), SOFTBUS_OK);
}

/*
 * @tc.name: TrySendSyncInfoMsgByAuth_001
 * @tc.desc: GetWifiDirectAuthByNetworkId(networkId, &authHandle) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, TrySendSyncInfoMsgByAuth_001, TestSize.Level1)
{
    SyncInfoMsg msg;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1);
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _)).Times(1);

    EXPECT_NE(TrySendSyncInfoMsgByAuth(NETWORKID, &msg), SOFTBUS_OK);
}

/*
 * @tc.name: TrySendSyncInfoMsgByAuth_002
 * @tc.desc: AuthPostTransData(authHandle, &dataInfo) == SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, TrySendSyncInfoMsgByAuth_002, TestSize.Level1)
{
    SyncInfoMsg msg;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1);
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(0)));

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(TrySendSyncInfoMsgByAuth(NETWORKID, &msg), SOFTBUS_ERR);
}

/*
 * @tc.name: TrySendSyncInfoMsgByAuth_003
 * @tc.desc: msg->complete != NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, TrySendSyncInfoMsgByAuth_003, TestSize.Level1)
{
    SyncInfoMsg *msg = CreateSyncInfoMsg(LNN_INFO_TYPE_CAPABILITY, MSG, LEN, Complete);
    if (msg == NULL) {
        LNN_LOGE(LNN_BUILDER, "create sync info msg error!");
        return;
    }
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnConvertDlId(_, _, _, _, _)).Times(1);
    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(0)));

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(TrySendSyncInfoMsgByAuth(NODE_NETWORK_ID, msg), SOFTBUS_ERR);
    SoftBusFree(msg);
}

/*
 * @tc.name: GetFeatureCap_001
 * @tc.desc: ret != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetFeatureCap_001, TestSize.Level1)
{
    uint64_t local = 0;
    uint64_t remote = 0;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_NE(GetFeatureCap(NETWORKID, &local, &remote), SOFTBUS_OK);
}

/*
 * @tc.name: GetFeatureCap_002
 * @tc.desc: *remote == 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetFeatureCap_002, TestSize.Level1)
{
    uint64_t local = 10;
    uint64_t remote = 0;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_NE(GetFeatureCap(NETWORKID, &local, &remote), SOFTBUS_OK);
}

/*
 * @tc.name: GetFeatureCap_003
 * @tc.desc: return SOFTBUS_OK;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetFeatureCap_003, TestSize.Level1)
{
    uint64_t local = 10;
    uint64_t remote = 10;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    NiceMock<LnnSyncInfoManagerInterfaceMock> mock;
    EXPECT_CALL(mock, LnnGetRemoteNumU64Info(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_EQ(GetFeatureCap(NETWORKID, &local, &remote), SOFTBUS_OK);
}

/*
 * @tc.name: IsNeedSyncByAuth_001
 * @tc.desc: LnnGetLocalNumU32Info(NUM_KEY_NET_CAP, &localCap) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_002
 * @tc.desc: (localCap & (1 << BIT_WIFI_P2P)) == 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_002, TestSize.Level1)
{
    uint32_t local = 0;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_003
 * @tc.desc: GetFeatureCap(networkId, &local, &remote) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_003, TestSize.Level1)
{
    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_004
 * @tc.desc: (local & (1 << BIT_BLE_TRIGGER_CONNECTION)) == 0
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_004, TestSize.Level1)
{
    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 1;
    uint32_t remote2 = 1;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_005
 * @tc.desc: LnnGetRemoteNodeInfoById(networkId, CATEGORY_NETWORK_ID, &node) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_005, TestSize.Level1)
{
    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 32768;
    uint32_t remote2 = 32768;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_006
 * @tc.desc: LnnHasDiscoveryType(&node, DISCOVERY_TYPE_WIFI) || LnnHasDiscoveryType(&node, DISCOVERY_TYPE_LSA)
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_006, TestSize.Level1)
{
    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 32768;
    uint32_t remote2 = 32768;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType(_, _)).Times(1).WillOnce(Return(true));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_007
 * @tc.desc: (localCap & (1 << BIT_BR)) && (remoteCap & (1 << BIT_BR))
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_007, TestSize.Level1)
{
    uint32_t local1 = 10;
    uint32_t remote1 = 10;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 32768;
    uint32_t remote2 = 32768;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType(_, _)).Times(2).WillOnce(Return(false)).WillOnce(Return(false));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), false);
}

/*
 * @tc.name: IsNeedSyncByAuth_008
 * @tc.desc: return true;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, IsNeedSyncByAuth_008, TestSize.Level1)
{
    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 32768;
    uint32_t remote2 = 32768;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType(_, _)).Times(2).WillOnce(Return(false)).WillOnce(Return(false));

    EXPECT_EQ(IsNeedSyncByAuth(NETWORKID), true);
}

/*
 * @tc.name: LnnSendSyncInfoMsg_001
 * @tc.desc: return true;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendSyncInfoMsg_001, TestSize.Level1)
{
    LnnSyncInfoType type = LNN_INFO_TYPE_CAPABILITY;

    uint32_t local1 = 8;
    uint32_t remote1 = 8;
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU32Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local1), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU32Info(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(remote1), Return(SOFTBUS_OK)));

    uint32_t local2 = 32768;
    uint32_t remote2 = 32768;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumU64Info(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<1>(local2), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, LnnGetRemoteNumU64Info(_, _, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<2>(remote2), Return(SOFTBUS_OK)));

    EXPECT_CALL(ledgerMock, LnnGetRemoteNodeInfoById(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnHasDiscoveryType(_, _)).Times(2).WillOnce(Return(false)).WillOnce(Return(false));

    EXPECT_CALL(ledgerMock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .WillOnce(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(0)));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    EXPECT_EQ(LnnSendSyncInfoMsg(type, NETWORKID, MSG, LEN, nullptr), SOFTBUS_OK);
}

/*
 * @tc.name: GetAuthHandleByNetworkId_001
 * @tc.desc: authHandle->authId != AUTH_INVALID_ID
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetAuthHandleByNetworkId_001, TestSize.Level1)
{
    AuthHandle authHandle;
    NiceMock<LnnNetLedgertInterfaceMock> mock;

    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(AuthHandle { .authId = 100, .type = 1 }), Return(0)));

    EXPECT_EQ(GetAuthHandleByNetworkId(NETWORKID, &authHandle), SOFTBUS_OK);
}

/*
 * @tc.name: GetAuthHandleByNetworkId_002
 * @tc.desc: return SOFTBUS_ERR;
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, GetAuthHandleByNetworkId_002, TestSize.Level1)
{
    AuthHandle authHandle;
    NiceMock<LnnNetLedgertInterfaceMock> mock;

    EXPECT_CALL(mock, LnnConvertDlId(_, _, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mock, AuthDeviceGetLatestIdByUuid(_, _, _))
        .WillRepeatedly(DoAll(SetArgPointee<2>(AuthHandle { .authId = AUTH_INVALID_ID, .type = 1 }), Return(0)));

    EXPECT_NE(GetAuthHandleByNetworkId(NETWORKID, &authHandle), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_001
 * @tc.desc: LnnGetLocalNumInfo(NUM_KEY_AUTH_PORT, &authPort) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_001, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _))
        .Times(2)
        .WillOnce(Return(SOFTBUS_ERR))
        .WillOnce(Return(SOFTBUS_OK));
    EXPECT_NE(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);

    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));
    EXPECT_NE(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_002
 * @tc.desc: ConvertBytesToHexString == SOFTBUS_ERR
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_002, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));

    EXPECT_NE(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_003
 * @tc.desc: msg == NULL
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_003, TestSize.Level1)
{
    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(nullptr));

    EXPECT_NE(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_004
 * @tc.desc: GetHmlOrP2pAuthHandle(&authHandle, &num) != SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_004, TestSize.Level1)
{
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddStringToObject(_, _, _)).WillRepeatedly(Return(true));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillOnce(Return(msg));

    EXPECT_CALL(lnnSyncInfoMgrMock, GetHmlOrP2pAuthHandle(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_NE(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_005
 * @tc.desc: AuthPostTransData(authHandle[i], &dataInfo) == SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_005, TestSize.Level1)
{
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    int32_t num = 1;
    AuthHandle *authHandle = new AuthHandle;
    authHandle->authId = 100;
    authHandle->type = 1;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddStringToObject(_, _, _)).WillRepeatedly(Return(true));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillOnce(Return(msg));

    EXPECT_CALL(lnnSyncInfoMgrMock, GetHmlOrP2pAuthHandle(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<0>(authHandle), SetArgPointee<1>(num), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));

    EXPECT_EQ(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}

/*
 * @tc.name: LnnSendWifiOfflineInfoMsg_006
 * @tc.desc: AuthPostTransData(authHandle[i], &dataInfo) == SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require: 1
 */
HWTEST_F(LNNSyncInfoManagerTest, LnnSendWifiOfflineInfoMsg_006, TestSize.Level1)
{
    char *msg = reinterpret_cast<char *>(SoftBusMalloc(LEN));
    if (msg == nullptr) {
        return;
    }
    (void)strcpy_s(msg, LEN, MSG_TEST);
    JsonObj json;
    (void)memset_s(&json, sizeof(JsonObj), 0, sizeof(JsonObj));
    int32_t num = 1;
    AuthHandle *authHandle = new AuthHandle;
    authHandle->authId = 100;
    authHandle->type = 1;

    NiceMock<LnnNetLedgertInterfaceMock> ledgerMock;
    NiceMock<LnnSyncInfoManagerInterfaceMock> lnnSyncInfoMgrMock;
    EXPECT_CALL(ledgerMock, LnnGetLocalNumInfo(_, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(ledgerMock, LnnGetLocalStrInfo(_, _, _)).Times(1).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(lnnSyncInfoMgrMock, ConvertBytesToHexString(_, _, _, _)).WillRepeatedly(Return(SOFTBUS_OK));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_CreateObject()).WillRepeatedly(Return(&json));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddInt32ToObject(_, _, _)).WillRepeatedly(Return(true));
    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_AddStringToObject(_, _, _)).WillRepeatedly(Return(true));

    EXPECT_CALL(lnnSyncInfoMgrMock, JSON_PrintUnformatted(_)).Times(1).WillOnce(Return(msg));

    EXPECT_CALL(lnnSyncInfoMgrMock, GetHmlOrP2pAuthHandle(_, _))
        .Times(1)
        .WillOnce(DoAll(SetArgPointee<0>(authHandle), SetArgPointee<1>(num), Return(SOFTBUS_OK)));
    EXPECT_CALL(lnnSyncInfoMgrMock, AuthPostTransData(_, _)).Times(1).WillOnce(Return(SOFTBUS_ERR));

    EXPECT_EQ(LnnSendWifiOfflineInfoMsg(), SOFTBUS_OK);
}
} // namespace OHOS
