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

#include <securec.h>

#include "auth_common.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "def.h"
#include "gtest/gtest.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "trans_channel_callback.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_udp_channel_manager.c"
#include "trans_udp_negotiation.h"
#include "trans_udp_negotiation_exchange.h"

using namespace testing::ext;

namespace OHOS {

#define TEST_AUTH_PORT (6000)
#define INVALID_CHANNEL_SEQ (22579)
#define INVALID_CHAN_ID (-1)
#define INVALID_CHANNEL_REQUETID (23456)
#define INVALID_CHANNEL_NETWORK (1111)
static int64_t g_channelId = 0;

class TransUdpManagerTest : public testing::Test {
public:
    TransUdpManagerTest()
    {}
    ~TransUdpManagerTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransUdpManagerTest::SetUpTestCase(void)
{
    int32_t ret = LnnInitBusCenterEvent();
    EXPECT_TRUE(SOFTBUS_OK == ret);
    ret = AuthCommonInit();
    EXPECT_TRUE(SOFTBUS_OK == ret);

    IServerChannelCallBack *cb = TransServerGetChannelCb();
    ret = TransUdpChannelInit(cb);
    EXPECT_TRUE(SOFTBUS_OK == ret);
}

void TransUdpManagerTest::TearDownTestCase(void)
{
    AuthCommonDeinit();
    TransUdpChannelDeinit();
    LnnDeinitBusCenterEvent();
}

int64_t TestGetChannelId()
{
    g_channelId++;
    return g_channelId;
}

UdpChannelInfo* GetPackTest()
{
    UdpChannelInfo *Channel = (UdpChannelInfo*)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (Channel == nullptr) {
        return nullptr;
    }
    Channel->info.myData.channelId = TestGetChannelId();
    Channel->info.appType = APP_TYPE_NORMAL;
    Channel->info.myData.apiVersion = API_V2;
    Channel->info.businessType = BUSINESS_TYPE_MESSAGE;
    Channel->info.peerData.apiVersion = API_V2;
    Channel->info.encrypt = APP_INFO_FILE_FEATURES_SUPPORT;
    Channel->info.algorithm = APP_INFO_ALGORITHM_AES_GCM_256;
    Channel->info.crc = APP_INFO_FILE_FEATURES_SUPPORT;
    (void)memcpy_s(Channel->info.groupId, GROUP_ID_SIZE_MAX, "123",
        (strlen("123")+1));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session", (strlen("com.test.trans.session")+1));
    (void)memcpy_s(Channel->info.peerNetWorkId, DEVICE_ID_SIZE_MAX,
        "1234567789", (strlen("1234567789")+1));
    (void)memcpy_s(Channel->info.peerData.sessionName, SESSION_NAME_SIZE_MAX,
        "com.test.trans.session.sendfile", (strlen("com.test.trans.session.sendfile")+1));
    (void)memcpy_s(Channel->info.sessionKey, SESSION_KEY_LENGTH,
        "auth session key", (strlen("auth session key")+1));
    (void)memcpy_s(Channel->info.myData.pkgName, PKG_NAME_SIZE_MAX,
        "normal pakName", (strlen("normal pakName")+1));
    (void)memcpy_s(Channel->info.myData.sessionName, SESSION_NAME_SIZE_MAX,
        "normal sessionName", (strlen("normal sessionName")+1));
    return Channel;
}

/**
 * @tc.name: TransUdpManagerTest001
 * @tc.desc: get lock and relsease lock.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest001, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = GetUdpChannelLock();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ReleaseUdpChannelLock();
    TransUdpChannelMgrDeinit();
    ret = GetUdpChannelLock();
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpManagerTest002
 * @tc.desc: udp channel init and deinit.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest002, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *newchannel = nullptr;
    ret = TransAddUdpChannel(newchannel);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);
    TransUdpChannelMgrDeinit();
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpManagerTest003
 * @tc.desc: add udp channel and del udp channel.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest003, TestSize.Level1)
{
    int32_t invalidId = -1;
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(NULL);
    EXPECT_TRUE(ret == SOFTBUS_INVALID_PARAM);

    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransAddUdpChannel(Channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransDelUdpChannel(invalidId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransDelUdpChannel(Channel->info.myData.channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransUdpChannelMgrDeinit();
    ret = TransAddUdpChannel(Channel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransDelUdpChannel(Channel->info.myData.channelId);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpManagerTest005
 * @tc.desc: get UdpChannelInfo by seq, use normal param.
 * @tc.type: FUNC
 * @tc.require: Zero
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest005, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    Channel->seq = 20;
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpChannelBySeq(Channel->seq, newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = TransDelUdpChannel(newChannel->info.myData.channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    SoftBusFree(newChannel);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest006
 * @tc.desc: get UdpChannelInfo by seq, use wrong param.
 * @tc.type: FUNC
 * @tc.require: NonZero
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest006, TestSize.Level1)
{
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    int64_t seq = INVALID_CHANNEL_SEQ;
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    TransUdpChannelMgrDeinit();
    int32_t ret = TransGetUdpChannelBySeq(Channel->seq, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpChannelMgrInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransAddUdpChannel(Channel);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpChannelBySeq(seq, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransGetUdpChannelBySeq(seq, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(newChannel);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest007
 * @tc.desc: get UdpChannelInfo by channelId, use normal param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest007, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    EXPECT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    ret = TransAddUdpChannel(Channel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransGetUdpChannelBySeq(Channel->requestId, newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransDelUdpChannel(newChannel->info.myData.channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
    SoftBusFree(newChannel);
}

/**
 * @tc.name: TransUdpManagerTest008
 * @tc.desc: get UdpChannelInfo by channelId, use wrong param.
 * @tc.type: FUNC
 * @tc.require: NonZero
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest008, TestSize.Level1)
{
    int64_t channlId = INVALID_CHAN_ID;
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    TransUdpChannelMgrDeinit();
    int32_t ret = TransGetUdpChannelById(Channel->info.myData.channelId, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpChannelById(channlId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransGetUdpChannelById(channlId, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
    SoftBusFree(newChannel);
}

/**
 * @tc.name: TransUdpManagerTest009
 * @tc.desc: get UdpChannelInfo by requestId, use normal param;
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest009, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpChannelByRequestId(Channel->requestId, newChannel);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    ret = TransDelUdpChannel(newChannel->info.myData.channelId);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
    SoftBusFree(newChannel);
}

/**
 * @tc.name: TransUdpManagerTest010
 * @tc.desc: get UdpChannelInfo by requestId, use wrong param;
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest010, TestSize.Level1)
{
    uint32_t requestId = INVALID_CHANNEL_REQUETID;
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    ASSERT_TRUE(newChannel != nullptr);
    (void)memset_s(newChannel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    newChannel->seq = 20;
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    TransUdpChannelMgrDeinit();
    int32_t ret = TransGetUdpChannelById(Channel->requestId, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret =TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpChannelByRequestId(requestId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransGetUdpChannelByRequestId(requestId, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransUdpChannelMgrDeinit();
    ret = TransGetUdpChannelByRequestId(requestId, newChannel);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    SoftBusFree(newChannel);
}

/**
 * @tc.name: TransUdpManagerTest011
 * @tc.desc: set UdpChannel status, use normal param first, then use wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest011, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t seq = INVALID_CHANNEL_SEQ;
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransSetUdpChannelStatus(Channel->seq, (UdpChannelStatus)UDP_CHANNEL_STATUS_INIT);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_INIT);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransSetUdpChannelStatus(seq, (UdpChannelStatus)UDP_CHANNEL_STATUS_INIT);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    TransUdpChannelMgrDeinit();
    ret = TransSetUdpChannelStatus(Channel->seq, (UdpChannelStatus)UDP_CHANNEL_STATUS_INIT);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpManagerTest012
 * @tc.desc: set UdpChannel opt type, use wrong param first, then use normal parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest012, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int64_t channelId = INVALID_CHAN_ID;
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransSetUdpChannelOptType(Channel->info.myData.channelId, (UdpChannelOptType)TYPE_UDP_CHANNEL_OPEN);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    ret = TransSetUdpChannelOptType(channelId, (UdpChannelOptType)TYPE_UDP_CHANNEL_OPEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransSetUdpChannelOptType(channelId, (UdpChannelOptType)TYPE_UDP_CHANNEL_OPEN);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest013
 * @tc.desc: update UdpChannelInfo by seq, use normal parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest013, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = 20;
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransUpdateUdpChannelInfo(Channel->seq, appInfo);
    TransUdpChannelMgrDeinit();
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpManagerTest014
 * @tc.desc: update UdpChannelInfo by seq, use wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest014, TestSize.Level1)
{
    int64_t seq = INVALID_CHANNEL_SEQ;
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = 20;
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    TransUdpChannelMgrDeinit();
    TransUpdateUdpChannelInfo(Channel->seq, appInfo);

    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransUpdateUdpChannelInfo(seq, NULL);
    TransUpdateUdpChannelInfo(Channel->seq, appInfo);
    TransUdpChannelMgrDeinit();
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpManagerTest015
 * @tc.desc: get pkgName and sessionName by channelId, use normal parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest015, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    char pkgName[65] = {"normal pakName"};
    char sessionName[256] = {"normal sessionName"};
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransUdpGetNameByChanId(Channel->info.myData.channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret == SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest016
 * @tc.desc: get pkgName and sessionName by channelId, use wrong parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest016, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int32_t channelId = INVALID_CHAN_ID;
    char pkgName[65] = {"wrong pakName"};
    char sessionName[256] = {"wrong sessionName"};
    UdpChannelInfo *Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ret = TransUdpGetNameByChanId(Channel->info.myData.channelId, pkgName, NULL,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpGetNameByChanId(channelId, NULL, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpGetNameByChanId(channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret != SOFTBUS_OK);

    ret = TransUdpGetNameByChanId(Channel->info.myData.channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransUdpChannelMgrDeinit();
    ret = TransUdpGetNameByChanId(Channel->info.myData.channelId, pkgName, sessionName,
        PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    EXPECT_TRUE(ret != SOFTBUS_OK);
}

/**
 * @tc.name: TransUdpManagerTest017
 * @tc.desc: trans get channel obj by channelId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest017, TestSize.Level1)
{
    int32_t channelId = INVALID_CHAN_ID;
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* Channel_1 = TransGetChannelObj(INVALID_CHAN_ID);
    EXPECT_TRUE(Channel_1 == nullptr);

    UdpChannelInfo* Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    Channel_1 = TransGetChannelObj(Channel->info.myData.channelId);
    EXPECT_TRUE(Channel != NULL);
    Channel_1 = TransGetChannelObj(channelId);
    EXPECT_TRUE(Channel_1 == NULL);

    TransUdpChannelMgrDeinit();
    Channel_1 = TransGetChannelObj(Channel->info.myData.channelId);
    EXPECT_TRUE(Channel_1 == NULL);
}

/**
 * @tc.name: TransUdpManagerTest018
 * @tc.desc: trans get channel obj by channelId, use normal param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest018, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = 20;
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpAppInfoByChannelId(Channel->info.myData.channelId, appInfo);
    EXPECT_TRUE(ret == SOFTBUS_OK);

    TransUdpChannelMgrDeinit();
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpManagerTest019
 * @tc.desc: trans get channel obj by channelId, use wrong param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest019, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    int32_t channelId = INVALID_CHAN_ID;
    UdpChannelInfo* Channel = GetPackTest();
    ASSERT_TRUE(Channel != nullptr);
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    ASSERT_TRUE(appInfo != nullptr);
    (void)memset_s(appInfo, sizeof(AppInfo), 0, sizeof(AppInfo));
    appInfo->myData.channelId = 20;
    ret = TransAddUdpChannel(Channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ret = TransGetUdpAppInfoByChannelId(channelId, appInfo);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    ret = TransGetUdpAppInfoByChannelId(channelId, NULL);
    EXPECT_TRUE(ret != SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransUdpManagerTest020
 * @tc.desc: trans notify udp channel close list.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest020, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* channel = GetPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ListNode udpDeleteChannelList;
    ListInit(&udpDeleteChannelList);
    NotifyUdpChannelCloseInList(&udpDeleteChannelList);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest021
 * @tc.desc: trans close udp channel by networkId.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest021, TestSize.Level1)
{
    string networkId = "invalid networlId";
    TransCloseUdpChannelByNetWorkId(networkId.c_str());
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransCloseUdpChannelByNetWorkId(NULL);
    UdpChannelInfo *channel = GetPackTest();
    ASSERT_TRUE(channel != nullptr);
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest022
 * @tc.desc: trans notify udp channel timeout use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest022, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* channel = GetPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ListNode udpTmpChannelList;
    ListInit(&udpTmpChannelList);
    NotifyTimeOutUdpChannel(&udpTmpChannelList);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest023
 * @tc.desc: trans notify udp channel timeout use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest023, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* channel = GetPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);

    ListNode udpTmpChannelList;
    ListInit(&udpTmpChannelList);
    NotifyTimeOutUdpChannel(&udpTmpChannelList);
    TransUdpChannelMgrDeinit();
}

/**
 * @tc.name: TransUdpManagerTest024
 * @tc.desc: trans notify udp channel timeout use diff param.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransUdpManagerTest, TransUdpManagerTest024, TestSize.Level1)
{
    int32_t ret = TransUdpChannelMgrInit();
    ASSERT_TRUE(ret == SOFTBUS_OK);
    UdpChannelInfo* channel = GetPackTest();
    ASSERT_TRUE(channel != nullptr);
    channel->info.udpChannelOptType = TYPE_INVALID_CHANNEL;
    ret = TransAddUdpChannel(channel);
    ASSERT_TRUE(ret == SOFTBUS_OK);
    ListNode udpTmpChannelList;
    ListInit(&udpTmpChannelList);
    NotifyTimeOutUdpChannel(&udpTmpChannelList);
    TransUdpChannelMgrDeinit();
}
}