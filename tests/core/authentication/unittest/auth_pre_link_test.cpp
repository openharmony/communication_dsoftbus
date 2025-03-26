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

#include "auth_pre_link.h"
#include "auth_attest_interface.h"
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

HWTEST_F(AuthPreLinkTest, ADD_AUTH_GEN_CER_PARA_NODE_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    int32_t ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_ALREADY_EXISTED);
    DelAuthGenCertParaNodeById(requestId);
}

HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isParallelGen = true;
    bool isValid = true;
    SoftbusCertChain *softbusCertChain = nullptr;
    int32_t ret = UpdateAuthGenCertParaNode(requestId, isParallelGen, isValid, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_002, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isParallelGen = true;
    bool isValid = true;
    SoftbusCertChain softbusCertChain;
    (void)memset_s(&softbusCertChain, sizeof(SoftbusCertChain), 0, sizeof(SoftbusCertChain));
    int32_t ret = UpdateAuthGenCertParaNode(requestId, isParallelGen, isValid, &softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

HWTEST_F(AuthPreLinkTest, UPDATE_AUTH_GEN_CER_PARA_NODE_TEST_003, TestSize.Level1)
{
    int32_t requestId = 1;
    bool isParallelGen = true;
    bool isValid = true;
    SoftbusCertChain *softbusCertChain = (SoftbusCertChain *)SoftBusCalloc(sizeof(SoftbusCertChain));
    ASSERT_NE(softbusCertChain, nullptr);
    int32_t ret = AddAuthGenCertParaNode(requestId);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UpdateAuthGenCertParaNode(requestId, isParallelGen, isValid, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_OK);
    isParallelGen = false;
    ret = UpdateAuthGenCertParaNode(requestId, isParallelGen, isValid, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthGenCertParaNodeById(requestId);
}

HWTEST_F(AuthPreLinkTest, FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_001, TestSize.Level1)
{
    int32_t requestId = 1;
    int32_t ret = FindAndWaitAuthGenCertParaNodeById(requestId, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

HWTEST_F(AuthPreLinkTest, FIND_AND_WAIT_AUTH_GEN_CERT_PARA_NODE_BY_ID_TEST_002, TestSize.Level1)
{
    int32_t requestId = 1;
    AuthGenCertNode *genCertParaNode = nullptr;
    int32_t ret = FindAndWaitAuthGenCertParaNodeById(requestId, &genCertParaNode);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
}

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
    ret = UpdateAuthGenCertParaNode(requestId, false, true, softbusCertChain);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = FindAndWaitAuthGenCertParaNodeById(requestId, &genCertParaNode);
    EXPECT_EQ(ret, SOFTBUS_OK);
    DelAuthGenCertParaNodeById(requestId);
}

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
}