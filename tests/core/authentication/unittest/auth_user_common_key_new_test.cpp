/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#include <cinttypes>
#include <gtest/gtest.h>
#include <securec.h>

#include "auth_uk_manager.h"
#include "auth_uk_manager.c"
#include "auth_user_common_key.h"

namespace OHOS {
using namespace testing;
using namespace testing::ext;

class AuthUserCommonKeyNewTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthUserCommonKeyNewTest::SetUpTestCase() { }

void AuthUserCommonKeyNewTest::TearDownTestCase() { }

void AuthUserCommonKeyNewTest::SetUp() { }

void AuthUserCommonKeyNewTest::TearDown() { }

/*
 * @tc.name: RequireUkNegotiateListLock001
 * @tc.desc: RequireUkNegotiateListLock false
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, RequireUkNegotiateListLock001, TestSize.Level0)
{
    EXPECT_FALSE(RequireUkNegotiateListLock());
}

/*
 * @tc.name: RequireUkNegotiateListLock002
 * @tc.desc: RequireUkNegotiateListLock false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, RequireUkNegotiateListLock002, TestSize.Level0)
{
    EXPECT_FALSE(RequireUkNegotiateListLock());
}

/*
 * @tc.name: ReleaseUkNegotiateListLock001, TestSize.Level0)
 * @tc.desc: SoftBusMutexUnlock  retur  SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, ReleaseUkNegotiateListLock001, TestSize.Level0)
{
    EXPECT_EQ(SoftBusMutexUnlock(&g_ukNegotiateListLock), SOFTBUS_INVALID_PARAM);
    ReleaseUkNegotiateListLock();
}

/*
 * @tc.name: ReleaseUkNegotiateListLock002
 * @tc.desc: SoftBusMutexUnlock is not SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, ReleaseUkNegotiateListLock002, TestSize.Level0)
{
    EXPECT_NE(SoftBusMutexUnlock(&g_ukNegotiateListLock), SOFTBUS_OK);
    ReleaseUkNegotiateListLock();
}

/*
 * @tc.name: InitUkNegoInstanceList001
 * @tc.desc: InitUkNegoInstanceList return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, InitUkNegoInstanceList001, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: InitUkNegoInstanceList002
 * @tc.desc: InitUkNegoInstanceList return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, InitUkNegoInstanceList002, TestSize.Level0)
{
    g_ukNegotiateList = NULL;
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
    EXPECT_NE(g_ukNegotiateList, NULL);
    EXPECT_EQ(g_ukNegotiateList->cnt, 0);
}

/*
 * @tc.name: InitUkNegoInstanceList003
 * @tc.desc: InitUkNegoInstanceList return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, InitUkNegoInstanceList003, TestSize.Level0)
{
    EXPECT_EQ(InitUkNegoInstanceList(), SOFTBUS_OK);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest001
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest001, TestSize.Level0)
{
    g_ukNegotiateList = NULL;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    EXPECT_EQ(GetGenUkInstanceByChannel(1, &instance), SOFTBUS_NO_INIT);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest002
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest002, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    EXPECT_EQ(GetGenUkInstanceByChannel(1, NULL), SOFTBUS_INVALID_PARAM);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest003
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest003, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    EXPECT_EQ(GetGenUkInstanceByChannel(1, &instance), SOFTBUS_LOCK_ERR);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest004
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest004, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    instance.channelId = 1;
    g_ukNegotiateList->list.next = &instance.node;
    EXPECT_EQ(GetGenUkInstanceByChannel(1, &instance), SOFTBUS_LOCK_ERR);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest005
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest005, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    EXPECT_EQ(GetGenUkInstanceByChannel(1, &instance), SOFTBUS_LOCK_ERR);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByChannelTest006
 * @tc.desc: GetGenUkInstanceByChannel return SOFTBUS_MEM_ERPR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByChannelTest006, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    g_ukNegotiateList->list.next = &instance.node;
    instance.channelId = 1;
    EXPECT_EQ(GetGenUkInstanceByChannel(1, &instance), SOFTBUS_LOCK_ERR);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: GetSameUkInstanceNumTest001
 * @tc.desc: GetSameUkInstanceNum return 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetSameUkInstanceNumTest001, TestSize.Level0)
{
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    info.isServer = true;
    info.sourceUserId = 1;
    info.sinkUserId = 2;
    info.sourceTokenId = 100;
    info.sinkTokenId = 200;
    strcpy_s(info.sourceUdid, sizeof(info.sourceUdid), "sourceUdid");
    strcpy_s(info.sinkUdid, sizeof(info.sinkUdid), "sinkUdid");
    strcpy_s(info.sourceAccountId, sizeof(info.sourceAccountId), "sourceAccountId");
    strcpy_s(info.sinkAccountId, sizeof(info.sinkAccountId), "sinkAccountId");
    EXPECT_EQ(GetSameUkInstanceNum(&info), 0);
}

/*
 * @tc.name: GetSameUkInstanceNumTest002
 * @tc.desc: GetSameUkInstanceNum return 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetSameUkInstanceNumTest002, TestSize.Level0)
{
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    info.isServer = true;
    info.sourceUserId = 1;
    info.sinkUserId = 2;
    info.sourceTokenId = 100;
    info.sinkTokenId = 200;
    strcpy_s(info.sourceUdid, sizeof(info.sourceUdid), "sourceUdid");
    strcpy_s(info.sinkUdid, sizeof(info.sinkUdid), "sinkUdid");
    strcpy_s(info.sourceAccountId, sizeof(info.sourceAccountId), "sourceAccountId");
    strcpy_s(info.sinkAccountId, sizeof(info.sinkAccountId), "sinkAccountId");
    EXPECT_EQ(GetSameUkInstanceNum(&info), 0);
}

/*
 * @tc.name: GetSameUkInstanceNumTest003
 * @tc.desc: GetSameUkInstanceNum return 0
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetSameUkInstanceNumTest003, TestSize.Level0)
{
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    info.isServer = true;
    info.sourceUserId = 1;
    info.sinkUserId = 2;
    info.sourceTokenId = 100;
    info.sinkTokenId = 200;
    strcpy_s(info.sourceUdid, sizeof(info.sourceUdid), "sourceUdid");
    strcpy_s(info.sinkUdid, sizeof(info.sinkUdid), "sinkUdid");
    strcpy_s(info.sourceAccountId, sizeof(info.sourceAccountId), "sourceAccountId");
    strcpy_s(info.sinkAccountId, sizeof(info.sinkAccountId), "sinkAccountId");
    EXPECT_EQ(GetSameUkInstanceNum(&info), 0);
}

/*
 * @tc.name: GetGenUkInstanceByReqTest001
 * @tc.desc: GetGenUkInstanceByReq return SOFTBUS_NO_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByReqTest001, TestSize.Level0)
{
    g_ukNegotiateList = NULL;
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t result = GetGenUkInstanceByReq(1, &instance);
    EXPECT_EQ(result, SOFTBUS_NO_INIT);
}

/*
 * @tc.name: GetGenUkInstanceByReqTest002
 * @tc.desc: GetGenUkInstanceByReq return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByReqTest002, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t result = GetGenUkInstanceByReq(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByReqTest003
 * @tc.desc: GetGenUkInstanceByReq return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByReqTest003, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance  instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    instance.requestId = 1;
    int32_t result = GetGenUkInstanceByReq(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByReqTest004
 * @tc.desc: GetGenUkInstanceByReq return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByReqTest004, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    instance.requestId = 1;
    int32_t result = GetGenUkInstanceByReq(1, NULL);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: GetGenUkInstanceByReqTest005
 * @tc.desc: GetGenUkInstanceByReq return SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, GetGenUkInstanceByReqTest005, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t result = GetGenUkInstanceByReq(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: PrintfAuthAclInfoTest001
 * @tc.desc: PrintfAuthAclInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, PrintfAuthAclInfoTest001, TestSize.Level0)
{
    uint32_t requestId = 1;
    uint32_t channelId = 2;
    const AuthACLInfo *info = NULL;
    EXPECT_NO_FATAL_FAILURE(PrintfAuthAclInfo(requestId, channelId, info));
}

/*
 * @tc.name: PrintfAuthAclInfoTest002
 * @tc.desc: PrintfAuthAclInfo test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, PrintfAuthAclInfoTest002, TestSize.Level0)
{
    uint32_t requestId = 1;
    uint32_t channelId = 2;
    AuthACLInfo info;
    (void)memset_s(&info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    info.isServer = true;
    info.sourceUserId = 100;
    info.sinkUserId = 200;
    info.sourceTokenId = 1000;
    info.sinkTokenId = 2000;
    strcpy_s(info.sourceUdid, 20, "sourceUdid");
    strcpy_s(info.sinkUdid, 20, "sinkUdid");
    strcpy_s(info.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(info.sinkAccountId, 20, "sinkAccountId");
    EXPECT_NO_FATAL_FAILURE(PrintfAuthAclInfo(requestId, channelId, &info));
}

/*
 * @tc.name: CreateUkNegotiateInstanceTest001
 * @tc.desc: CreateUkNegotiateInstance return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CreateUkNegotiateInstanceTest001, TestSize.Level0)
{
    uint32_t requestId = 1;
    uint32_t channelId = 1;
    AuthACLInfo info = {0};
    AuthGenUkCallback genCb = {0};
    int32_t ret = CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: CreateUkNegotiateInstanceTest002
 * @tc.desc: CreateUkNegotiateInstance return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CreateUkNegotiateInstanceTest002, TestSize.Level0)
{
    uint32_t requestId = 1;
    uint32_t channelId = 1;
    AuthACLInfo info = {1};
    AuthGenUkCallback genCb = {0};
    int32_t ret = CreateUkNegotiateInstance(requestId, channelId, &info, &genCb);
    EXPECT_EQ(ret, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: UpdateUkNegotiateInfoTest001
 * @tc.desc: UpdateUkNegotiateInfo return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, UpdateUkNegotiateInfoTest001, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    int32_t result = UpdateUkNegotiateInfo(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: UpdateUkNegotiateInfoTest002
 * @tc.desc: UpdateUkNegotiateInfo return  SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, UpdateUkNegotiateInfoTest002, TestSize.Level0)
{
    UkNegotiateInstance *instance = nullptr;
    int32_t result = UpdateUkNegotiateInfo(1, instance);
    EXPECT_EQ(result, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UpdateUkNegotiateInfoTest003
 * @tc.desc: UpdateUkNegotiateInfo return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, UpdateUkNegotiateInfoTest003, TestSize.Level0)
{
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    int32_t result = UpdateUkNegotiateInfo(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: UpdateUkNegotiateInfoTest004
 * @tc.desc: UpdateUkNegotiateInfo return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, UpdateUkNegotiateInfoTest004, TestSize.Level0)
{
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    instance.requestId = 1;
    instance.ukId = 123;
    instance.channelId = 456;
    instance.keyLen = 128;
    instance.authMode = HICHAIN_AUTH_DEVICE;
    instance.state = GENUK_STATE_START;
    instance.negoInfo.isRecvSessionKeyEvent = true;
    instance.negoInfo.isRecvFinishEvent = false;
    instance.negoInfo.isRecvCloseAckEvent = false;
    (void)memset_s(&instance.info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    int32_t result = UpdateUkNegotiateInfo(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
}

/*
 * @tc.name: UpdateUkNegotiateInfoTest005
 * @tc.desc: UpdateUkNegotiateInfo return  SOFTBUS_LOCK_ERR
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, UpdateUkNegotiateInfoTest005, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    UkNegotiateInstance instance;
    (void)memset_s(&instance, sizeof(UkNegotiateInstance), 0, sizeof(UkNegotiateInstance));
    instance.requestId = 1;
    instance.ukId = 123;
    instance.channelId = 456;
    instance.keyLen = 128;
    instance.authMode = HICHAIN_AUTH_DEVICE;
    instance.state = GENUK_STATE_START;
    instance.negoInfo.isRecvSessionKeyEvent = true;
    instance.negoInfo.isRecvFinishEvent = false;
    instance.negoInfo.isRecvCloseAckEvent = false;
    (void)memset_s(&instance.info, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    int32_t result = UpdateUkNegotiateInfo(1, &instance);
    EXPECT_EQ(result, SOFTBUS_LOCK_ERR);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: DeleteUkNegotiateInstanceTest001
 * @tc.desc: DeleteUkNegotiateInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, DeleteUkNegotiateInstanceTest001, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    uint32_t requestId = 1234567;
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(requestId));
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: DeleteUkNegotiateInstanceTest002
 * @tc.desc: DeleteUkNegotiateInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, DeleteUkNegotiateInstanceTest002, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    uint32_t requestId = 0;
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(requestId));
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: DeleteUkNegotiateInstanceTest003
 * @tc.desc: DeleteUkNegotiateInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, DeleteUkNegotiateInstanceTest003, TestSize.Level0)
{
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(1));
}

/*
 * @tc.name: DeleteUkNegotiateInstanceTest004
 * @tc.desc: DeleteUkNegotiateInstance test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, DeleteUkNegotiateInstanceTest004, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    g_ukNegotiateList->list.next = &g_ukNegotiateList->list;
    g_ukNegotiateList->list.prev = &g_ukNegotiateList->list;
    EXPECT_NO_FATAL_FAILURE(DeleteUkNegotiateInstance(1));
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: CompareByAllAclTest001
 * @tc.desc: CompareByAllAcl return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest001, TestSize.Level0)
{
    g_ukNegotiateList = (SoftBusList*)SoftBusMalloc(sizeof(SoftBusList));
    ASSERT_NE(g_ukNegotiateList, nullptr);
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 2;
    oldAcl.sourceTokenId = 100;
    oldAcl.sinkTokenId = 200;
    strcpy_s(oldAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, 20, "sinkAccountId");
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    newAcl.isServer = true;
    newAcl.sourceUserId = 2;
    newAcl.sinkUserId = 1;
    newAcl.sourceTokenId = 300;
    newAcl.sinkTokenId = 400;
    strcpy_s(newAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(newAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(newAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(newAcl.sinkAccountId, 20, "sinkAccountId");
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, true);
    EXPECT_FALSE(ret);
    SoftBusFree(g_ukNegotiateList);
}

/*
 * @tc.name: CompareByAllAclTest002
 * @tc.desc: CompareByAllAcl return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest002, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 2;
    oldAcl.sourceTokenId = 100;
    oldAcl.sinkTokenId = 200;
    strcpy_s(oldAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, 20, "sinkAccountId");
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    newAcl.isServer = true;
    newAcl.sourceUserId = 2;
    newAcl.sinkUserId = 1;
    newAcl.sourceTokenId = 300;
    newAcl.sinkTokenId = 400;
    strcpy_s(newAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(newAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(newAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(newAcl.sinkAccountId, 20, "sinkAccountId");
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, false);
    EXPECT_FALSE(ret);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: CompareByAllAclTest003
 * @tc.desc: CompareByAllAcl return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest003, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 2;
    oldAcl.sourceTokenId = 100;
    oldAcl.sinkTokenId = 200;
    strcpy_s(oldAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, 20, "sinkAccountId");
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    newAcl.isServer = true;
    newAcl.sourceUserId = 2;
    newAcl.sinkUserId = 1;
    newAcl.sourceTokenId = 300;
    newAcl.sinkTokenId = 400;
    strcpy_s(newAcl.sourceUdid, 20, "sourceUdid");
    strcpy_s(newAcl.sinkUdid, 20, "sinkUdid");
    strcpy_s(newAcl.sourceAccountId, 20, "sourceAccountId");
    strcpy_s(newAcl.sinkAccountId, 20, "sinkAccountId");
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, false);
    EXPECT_FALSE(ret);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: CompareByAllAclTest004
 * @tc.desc: CompareByAllAcl return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest004, TestSize.Level0)
{
    g_ukNegotiateList = CreateSoftBusList();
    ASSERT_NE(g_ukNegotiateList, nullptr);
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 2;
    oldAcl.sourceTokenId = 100;
    oldAcl.sinkTokenId = 200;
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, sizeof(oldAcl.sourceAccountId), "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, sizeof(oldAcl.sinkAccountId), "sinkAccountId");
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    newAcl.isServer = true;
    newAcl.sourceUserId = 2;
    newAcl.sinkUserId = 1;
    newAcl.sourceTokenId = 300;
    newAcl.sinkTokenId = 400;
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "sourceUdid");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "sinkUdid");
    strcpy_s(newAcl.sourceAccountId, sizeof(newAcl.sourceAccountId), "sourceAccountId");
    strcpy_s(newAcl.sinkAccountId, sizeof(newAcl.sinkAccountId), "sinkAccountId");
    bool ret = CompareByAllAcl(&oldAcl, &newAcl, true);
    EXPECT_FALSE(ret);
    DestroySoftBusList(g_ukNegotiateList);
}

/*
 * @tc.name: CompareByAllAclTest005
 * @tc.desc: CompareByAllAclTest return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest005, TestSize.Level0)
{
    const AuthACLInfo* oldAcl = nullptr;
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    newAcl.isServer = true;
    newAcl.sourceUserId = 1;
    newAcl.sinkUserId = 1;
    newAcl.sourceTokenId = 123456;
    newAcl.sinkTokenId = 123456;
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "sourceUdid");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "sinkUdid");
    strcpy_s(newAcl.sourceAccountId, sizeof(newAcl.sourceAccountId), "sourceAccountId");
    strcpy_s(newAcl.sinkAccountId, sizeof(newAcl.sinkAccountId), "sinkAccountId");
    EXPECT_FALSE(CompareByAllAcl(oldAcl, &newAcl, true));
}

/*
 * @tc.name: CompareByAllAclTest006
 * @tc.desc: CompareByAllAcl return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest006, TestSize.Level0)
{
    const AuthACLInfo* newAcl = nullptr;
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 1;
    oldAcl.sourceTokenId = 123456;
    oldAcl.sinkTokenId = 123456;
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, sizeof(oldAcl.sourceAccountId), "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, sizeof(oldAcl.sinkAccountId), "sinkAccountId");
    EXPECT_FALSE(CompareByAllAcl(&oldAcl, newAcl, true));
}

/*
 * @tc.name: CompareByAllAclTest007
 * @tc.desc: CompareByAllAcl return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAllAclTest007, TestSize.Level0)
{
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    oldAcl.isServer = true;
    oldAcl.sourceUserId = 1;
    oldAcl.sinkUserId = 1;
    oldAcl.sourceTokenId = 123456;
    oldAcl.sinkTokenId = 123456;
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "sourceUdid");
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "sinkUdid");
    strcpy_s(oldAcl.sourceAccountId, sizeof(oldAcl.sourceAccountId), "sourceAccountId");
    strcpy_s(oldAcl.sinkAccountId, sizeof(oldAcl.sinkAccountId), "sinkAccountId");
    EXPECT_TRUE(CompareByAllAcl(&oldAcl, &oldAcl, true));
}

/*
 * @tc.name: CompareByAclDiffAccountWithUserLevelTest001
 * @tc.desc: CompareByAclDiffAccountWithUserLevel return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAclDiffAccountWithUserLevelTest001, TestSize.Level0)
{
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "udid1");
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "udid1");
    oldAcl.sourceUserId = 1;
    newAcl.sourceUserId = 1;
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "udid2");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "udid2");
    oldAcl.sinkUserId = 2;
    newAcl.sinkUserId = 2;
    EXPECT_TRUE(CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, true));
}

/*
 * @tc.name: CompareByAclDiffAccountWithUserLevelTest002
 * @tc.desc: CompareByAclDiffAccountWithUserLevel return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAclDiffAccountWithUserLevelTest002, TestSize.Level0)
{
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "udid1");
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "udid2");
    oldAcl.sourceUserId = 1;
    newAcl.sourceUserId = 1;
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "udid2");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "udid2");
    oldAcl.sinkUserId = 2;
    newAcl.sinkUserId = 2;
    EXPECT_FALSE(CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, true));
}

/*
 * @tc.name: CompareByAclDiffAccountWithUserLevelTest003
 * @tc.desc: CompareByAclDiffAccountWithUserLevel return true
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAclDiffAccountWithUserLevelTest003, TestSize.Level0)
{
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "udid1");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "udid1");
    oldAcl.sourceUserId = 1;
    newAcl.sinkUserId = 1;
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "udid2");
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "udid2");
    oldAcl.sinkUserId = 2;
    newAcl.sourceUserId = 2;
    EXPECT_TRUE(CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, false));
}

/*
 * @tc.name: CompareByAclDiffAccountWithUserLevelTest004
 * @tc.desc: CompareByAclDiffAccountWithUserLevel return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAclDiffAccountWithUserLevelTest004, TestSize.Level0)
{
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    EXPECT_FALSE(CompareByAclDiffAccountWithUserLevel(nullptr, &newAcl, true));
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    EXPECT_FALSE(CompareByAclDiffAccountWithUserLevel(&oldAcl, nullptr, true));
    EXPECT_FALSE(CompareByAclDiffAccountWithUserLevel(nullptr, nullptr, true));
}

/*
 * @tc.name: CompareByAclDiffAccountWithUserLevelTest005
 * @tc.desc: CompareByAclDiffAccountWithUserLevel return false
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthUserCommonKeyNewTest, CompareByAclDiffAccountWithUserLevelTest005, TestSize.Level0)
{
    AuthACLInfo newAcl;
    (void)memset_s(&newAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    AuthACLInfo oldAcl;
    (void)memset_s(&oldAcl, sizeof(AuthACLInfo), 0, sizeof(AuthACLInfo));
    strcpy_s(oldAcl.sourceUdid, sizeof(oldAcl.sourceUdid), "udid1");
    strcpy_s(newAcl.sinkUdid, sizeof(newAcl.sinkUdid), "udid2");
    oldAcl.sourceUserId = 1;
    newAcl.sinkUserId = 1;
    strcpy_s(oldAcl.sinkUdid, sizeof(oldAcl.sinkUdid), "udid2");
    strcpy_s(newAcl.sourceUdid, sizeof(newAcl.sourceUdid), "udid2");
    oldAcl.sinkUserId = 2;
    newAcl.sourceUserId = 2;
    EXPECT_FALSE(CompareByAclDiffAccountWithUserLevel(&oldAcl, &newAcl, false));
}
}