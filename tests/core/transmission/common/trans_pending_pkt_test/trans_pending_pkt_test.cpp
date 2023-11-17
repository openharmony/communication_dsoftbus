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

#include "gtest/gtest.h"
#include "session.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_protocol_def.h"
#include "trans_pending_pkt.h"
#include "trans_pending_pkt.c"

using namespace testing::ext;
namespace OHOS {
class TransPendingPktTest : public testing::Test {
public:
    TransPendingPktTest()
    {}
    ~TransPendingPktTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransPendingPktTest::SetUpTestCase(void)
{}

void TransPendingPktTest::TearDownTestCase(void)
{}

/**
 * @tc.name: PendingInit001
 * @tc.desc: PendingInit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, PendingInit001, TestSize.Level1)
{
    int type = -88;
    int32_t ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = 999;
    ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = PENDING_TYPE_DIRECT;
    ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: PendingDeinit001
 * @tc.desc: PendingDeinit001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, PendingDeinit001, TestSize.Level1)
{
    int type = -21;
    PendingDeinit(type);

    type = 999;
    PendingDeinit(type);

    type = PENDING_TYPE_DIRECT;
    int32_t ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    PendingDeinit(type);
}

/**
 * @tc.name: CreatePendingItem001
 * @tc.desc: CreatePendingItem001, use the wrong parameter.
 * @tc.desc: ReleasePendingItem, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, CreatePendingItem001, TestSize.Level1)
{
    int32_t seqNum = 1111;
    int32_t channelId = 222;
    PendingPktInfo *item = NULL;
    item = CreatePendingItem(channelId, seqNum);
    EXPECT_TRUE(item != NULL);

    ReleasePendingItem(item);
    ReleasePendingItem(NULL);
}

/**
 * @tc.name: ProcPendingPacket001
 * @tc.desc: ProcPendingPacket001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, ProcPendingPacket001, TestSize.Level1)
{
    int32_t seqNum = 1111;
    int32_t channelId = 222;
    int type = PENDING_TYPE_BUTT + 1;
    int32_t ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    type = PENDING_TYPE_PROXY - 1;
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = PENDING_TYPE_PROXY + 1;
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND, ret);
}

/**
 * @tc.name: SetPendingPacket001
 * @tc.desc: SetPendingPacket001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, SetPendingPacket001, TestSize.Level1)
{
    int32_t channelId = 1111;
    int32_t seqNum = 222;
    int type = PENDING_TYPE_BUTT + 1;
    int32_t ret = SetPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    type = PENDING_TYPE_PROXY - 1;
    ret = SetPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = PENDING_TYPE_DIRECT;
    channelId = -1;
    ret = SetPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: DelPendingPacket001
 * @tc.desc: DelPendingPacket001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, DelPendingPacket001, TestSize.Level1)
{
    int32_t channelId = 1111;
    int type = PENDING_TYPE_BUTT + 1;
    int32_t ret = DelPendingPacket(channelId, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);
    type = PENDING_TYPE_PROXY - 1;
    ret = DelPendingPacket(channelId, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = PENDING_TYPE_PROXY + 1;
    PendingDeinit(type);
    ret = DelPendingPacket(channelId, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: ProcPendingPacket002
 * @tc.desc: ProcPendingPacket, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, ProcPendingPacket002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t seqNum = 0;
    int type = 1;

    int32_t ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND, ret);

    type = -1;
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    type = 1;
    ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_TIMOUT, ret);
}

/**
 * @tc.name: TimeBefore001
 * @tc.desc: TimeBefore001, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, TimeBefore001, TestSize.Level1)
{
    SoftBusSysTime outtime;
    SoftBusSysTime now;
    SoftBusGetTime(&now);
    outtime.sec = now.sec + TIME_OUT;
    outtime.usec = now.usec;
    bool res = TimeBefore(&outtime);
    EXPECT_TRUE(res);
}

/**
 * @tc.name: ProcPendingPacket002
 * @tc.desc: ProcPendingPacket, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, SetPendingPacket002, TestSize.Level1)
{
    int32_t channelId = 1;
    int32_t seqNum = 0;
    int type = 1;

    int32_t ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ProcPendingPacket(channelId, seqNum, type);
    ret = SetPendingPacket(channelId, seqNum, type);
    EXPECT_EQ(SOFTBUS_ERR, ret);

    PendingDeinit(type);
}

/**
 * @tc.name: DelPendingPacket002
 * @tc.desc: DelPendingPacket002, use the wrong parameter.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransPendingPktTest, DelPendingPacket002, TestSize.Level1)
{
    int32_t channelId = 1;
    int type = 1;
    int32_t seqNum = 0;

    int ret = PendingInit(type);
    EXPECT_EQ(SOFTBUS_OK, ret);
    ret = ProcPendingPacket(channelId, seqNum, type);
    EXPECT_NE(SOFTBUS_ERR, ret);
    ret = DelPendingPacket(channelId, type);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

} // OHOS
