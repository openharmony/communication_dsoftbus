/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <gtest/gtest.h>
#include <securec.h>

#include "auth_pre_link.c"
#include "auth_pre_link.h"
#include "auth_pre_link_mock.h"
#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"

namespace OHOS {
using namespace testing::ext;
using namespace testing;
const int32_t TEST_FD = 1;
const char TEST_UUID[] = "1234567890";

class AuthPreLinkTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void AuthPreLinkTest::SetUpTestCase()
{
    int32_t ret = InitAuthPreLinkList();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitAuthGenCertParallelList();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

void AuthPreLinkTest::TearDownTestCase()
{
    DeinitAuthGenCertParallelList();
    DeinitAuthPreLinkList();
}

void AuthPreLinkTest::SetUp() { }

void AuthPreLinkTest::TearDown() { }

static bool AuthFsmTestTrueLinkHasPtk(const char *remoteDeviceId)
{
    (void)remoteDeviceId;
    return true;
}

static bool AuthFsmTestFalseLinkHasPtk(const char *remoteDeviceId)
{
    (void)remoteDeviceId;
    return false;
}

static struct WifiDirectManager g_manager1 = {
    .linkHasPtk = AuthFsmTestTrueLinkHasPtk,
};

static struct WifiDirectManager g_manager2 = {
    .linkHasPtk = AuthFsmTestFalseLinkHasPtk,
};

static struct WifiDirectManager g_manager3 = {
    .linkHasPtk = NULL,
};

/*
 * @tc.name: ADD_AUTH_GEN_CER_PARA_NODE_TEST_001
 * @tc.desc: Verify that AddAuthGenCertParaNode correctly adds a node to the authentication
 *           certificate parallel list and handles existing nodes.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, ADD_AUTH_GEN_CER_PARA_NODE_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    int32_t ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_EXISTED);
    DelAuthGenCertParaNodeById(requestId);
}

/*
 * @tc.name: UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_001
 * @tc.desc: Verify that UpdateAuthGenCertParaNode returns an invalid parameter error when
 *           provided with a null SoftbusCertChain.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isValid = true;
    SoftbusCertChain *softbusCertChain = nullptr;
    int32_t ret = UpdateAuthGenCertParaNode(requestId, isValid, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_002
 * @tc.desc: Verify that UpdateAuthGenCertParaNode returns SOFTBUS_NOT_FIND when the specified
 *           request ID is not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_002, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isValid = true;
    SoftbusCertChain softbusCertChain;
    (void)memset_s(&softbusCertChain, sizeof(SoftbusCertChain), 0, sizeof(SoftbusCertChain));
    int32_t ret = UpdateAuthGenCertParaNode(requestId, isValid, &softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_003
 * @tc.desc: Verify that UpdateAuthGenCertParaNode successfully updates an authentication
 *           certificate parallel node.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_003, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isValid = true;
    SoftbusCertChain *softbusCertChain = (SoftbusCertChain *)SoftBusCalloc(sizeof(SoftbusCertChain));
    ASSERT_NE(softbusCertChain, nullptr);
    int32_t ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateAuthGenCertParaNode(requestId, isValid, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthGenCertParaNodeById(requestId);
}

/*
 * @tc.name: FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_001
 * @tc.desc: Verify that FindAndWaitAuthGenCertParaNodeById returns an invalid parameter error
 *           when provided with a null AuthGenCertNode pointer.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    int32_t ret = FindAndWaitAuthGenCertParaNodeById(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/*
 * @tc.name: FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_002
 * @tc.desc: Verify that FindAndWaitAuthGenCertParaNodeById returns SOFTBUS_NOT_FIND when the
 *           specified request ID is not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_002, TestSize.Level1)
{
    int32_t requestId = 1;
    AuthGenCertNode *genCertParaNode = nullptr;
    int32_t ret = FindAndWaitAuthGenCertParaNodeById(requestId, &genCertParaNode);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

/*
 * @tc.name: FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_003
 * @tc.desc: Verify that FindAndWaitAuthGenCertParaNodeById correctly finds and waits for an
 *           authentication certificate parallel node, handling timeouts and successful updates.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_003, TestSize.Level1)
{
    int32_t requestId = 1;
    AuthGenCertNode *genCertParaNode = nullptr;
    int32_t ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindAndWaitAuthGenCertParaNodeById(requestId, &genCertParaNode);
    EXPECT_EQ(ret, SOFTBUS_AUTH_TIMEOUT);
    ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    SoftbusCertChain *softbusCertChain = (SoftbusCertChain *)SoftBusCalloc(sizeof(SoftbusCertChain));
    ASSERT_NE(softbusCertChain, nullptr);
    ret = UpdateAuthGenCertParaNode(requestId, true, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindAndWaitAuthGenCertParaNodeById(requestId, &genCertParaNode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthGenCertParaNodeById(requestId);
}

/*
 * @tc.name: IS_AUTH_PRE_LINK_NODE_EXIST_TEST_001
 * @tc.desc: Verify that IsAuthPreLinkNodeExist correctly checks for the existence of an
 *           authentication pre-link node.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, IS_AUTH_PRE_LINK_NODE_EXIST_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    bool isExist = IsAuthPreLinkNodeExist(requestId);
    EXPECT_EQ(isExist, false);
    ConnectionAddr connAddr;
    (void)memset_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    int32_t ret = AddToAuthPreLinkList(requestId, TEST_FD, &connAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isExist = IsAuthPreLinkNodeExist(requestId);
    EXPECT_EQ(isExist, true);
    DelAuthPreLinkById(requestId);
}

/*
 * @tc.name: FIND_AUTH_PRE_LINK_NODE_BY_ID_TEST_001
 * @tc.desc: Verify that FindAuthPreLinkNodeById correctly finds an authentication pre-link node
 *           by its ID.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, FIND_AUTH_PRE_LINK_NODE_BY_ID_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthPreLinkNode node;
    (void)memset_s(&node, sizeof(AuthPreLinkNode), 0, sizeof(ConnectionAddr));
    int32_t ret = FindAuthPreLinkNodeById(requestId, &node);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ConnectionAddr connAddr;
    (void)memset_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ret = AddToAuthPreLinkList(requestId, TEST_FD, &connAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindAuthPreLinkNodeById(requestId, &node);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthPreLinkById(requestId);
}

/*
 * @tc.name: FIND_AUTH_PRE_LINK_NODE_BY_UUID_TEST_001
 * @tc.desc: Verify that FindAuthPreLinkNodeByUuid correctly finds an authentication pre-link node
 *           by its UUID, handling null parameters and cases where the node is not found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, FIND_AUTH_PRE_LINK_NODE_BY_UUID_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    AuthPreLinkNode node;
    (void)memset_s(&node, sizeof(AuthPreLinkNode), 0, sizeof(ConnectionAddr));
    int32_t ret = FindAuthPreLinkNodeByUuid(nullptr, &node);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = FindAuthPreLinkNodeByUuid(TEST_UUID, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = FindAuthPreLinkNodeByUuid(TEST_UUID, &node);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ConnectionAddr connAddr;
    (void)memset_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ret = AddToAuthPreLinkList(requestId, TEST_FD, &connAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateAuthPreLinkUuidById(requestId, (char *)TEST_UUID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindAuthPreLinkNodeByUuid(TEST_UUID, &node);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthPreLinkById(requestId);
}

/*
 * @tc.name: UPDATE_AUTH_PRE_LINK_UUID_BY_ID_TEST_001
 * @tc.desc: Verify that UpdateAuthPreLinkUuidById correctly updates the UUID of an
 *           authentication pre-link node, handling null UUIDs and cases where the node is not
 *           found.
 * @tc.type: FUNC
 * @tc.level: Level1
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_PRE_LINK_UUID_BY_ID_TEST_001, TestSize.Level1)
{
    uint32_t requestId = 1;
    int32_t ret = UpdateAuthPreLinkUuidById(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = UpdateAuthPreLinkUuidById(requestId, (char *)TEST_UUID);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ConnectionAddr connAddr;
    (void)memset_s(&connAddr, sizeof(ConnectionAddr), 0, sizeof(ConnectionAddr));
    ret = AddToAuthPreLinkList(requestId, TEST_FD, &connAddr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateAuthPreLinkUuidById(requestId, (char *)TEST_UUID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthPreLinkById(requestId);
}

/*
 * @tc.name: PRE_LINK_CHECK_HAS_PTK_TEST_001
 * @tc.desc: PreLinkCheckHasPtk test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(AuthPreLinkTest, PRE_LINK_CHECK_HAS_PTK_TEST_001, TestSize.Level1)
{
    NiceMock<AuthPreLinkInterfaceMock> mock;
    EXPECT_CALL(mock, GetWifiDirectManager)
        .WillOnce(Return(NULL))
        .WillOnce(Return(&g_manager3))
        .WillOnce(Return(&g_manager2))
        .WillRepeatedly(Return(&g_manager1));
    EXPECT_FALSE(PreLinkCheckHasPtk(NULL));
    EXPECT_FALSE(PreLinkCheckHasPtk(TEST_UUID));
    EXPECT_FALSE(PreLinkCheckHasPtk(TEST_UUID));
    EXPECT_FALSE(PreLinkCheckHasPtk(TEST_UUID));
    EXPECT_TRUE(PreLinkCheckHasPtk(TEST_UUID));
}
} // namespace OHOS
