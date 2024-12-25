/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "bus_center_server_proxy.h"
#include "softbus_access_token_test.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"
#include "softbus_error_code.h"
#include "softbus_utils.h"

namespace OHOS {
using namespace testing::ext;

class BusCenterServerProxyTest : public testing::Test {
public:
    static void SetUpTestCase();
    static void TearDownTestCase();
    void SetUp();
    void TearDown();
};

void BusCenterServerProxyTest::SetUpTestCase() { }

void BusCenterServerProxyTest::TearDownTestCase() { }

void BusCenterServerProxyTest::SetUp() { }

void BusCenterServerProxyTest::TearDown() { }

/*
 * @tc.name: ServerIpcGetAllOnlineNodeInfo_TEST_001
 * @tc.desc: ServerIpcGetAllOnlineNodeInfo return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcGetAllOnlineNodeInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    void **info = nullptr;
    uint32_t infoTypeLen = 0;
    int32_t *infoNum = nullptr;
    int32_t ret = ServerIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcGetLocalDeviceInfo_TEST_001
 * @tc.desc: ServerIpcGetLocalDeviceInfo return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcGetLocalDeviceInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    void *info = nullptr;
    uint32_t infoTypeLen = 0;
    int32_t ret = ServerIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcGetNodeKeyInfo_TEST_001
 * @tc.desc: ServerIpcGetNodeKeyInfo return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcGetNodeKeyInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *networkId = "123";
    int32_t key = 1;
    unsigned char array[10] = { 0 };
    unsigned char *buf = array;
    uint32_t len = 0;
    int32_t ret = ServerIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcSetNodeDataChangeFlag_TEST_001
 * @tc.desc: ServerIpcSetNodeDataChangeFlag return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcSetNodeDataChangeFlag_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *networkId = "123";
    uint16_t dataChangeFlag = 0;
    int32_t ret = ServerIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcRegDataLevelChangeCb_TEST_001
 * @tc.desc: ServerIpcRegDataLevelChangeCb return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcRegDataLevelChangeCb_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    int32_t ret = ServerIpcRegDataLevelChangeCb(pkgName);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcUnregDataLevelChangeCb_TEST_001
 * @tc.desc: ServerIpcUnregDataLevelChangeCb return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcUnregDataLevelChangeCb_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    int32_t ret = ServerIpcUnregDataLevelChangeCb(pkgName);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcJoinLNN_TEST_001
 * @tc.desc: ServerIpcJoinLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcJoinLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    void *addr = nullptr;
    uint32_t addrTypeLen = 0;
    int32_t ret = ServerIpcJoinLNN(pkgName, addr, addrTypeLen);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcLeaveLNN_TEST_001
 * @tc.desc: ServerIpcLeaveLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcLeaveLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *networkId = "123";
    int32_t ret = ServerIpcLeaveLNN(pkgName, networkId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcStartTimeSync_TEST_001
 * @tc.desc: ServerIpcStartTimeSync return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcStartTimeSync_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *targetNetworkId = "111";
    int32_t accuracy = 1;
    int32_t period = 1;
    int32_t ret = ServerIpcStartTimeSync(pkgName, targetNetworkId, accuracy, period);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcStopTimeSync_TEST_001
 * @tc.desc: ServerIpcStopTimeSync return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcStopTimeSync_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *targetNetworkId = "1234";
    int32_t ret = ServerIpcStopTimeSync(pkgName, targetNetworkId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcPublishLNN_TEST_001
 * @tc.desc: ServerIpcPublishLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcPublishLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const PublishInfo *info = nullptr;
    int32_t ret = ServerIpcPublishLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcStopPublishLNN_TEST_001
 * @tc.desc: ServerIpcStopPublishLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcStopPublishLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    int32_t publishId = 123;
    int32_t ret = ServerIpcStopPublishLNN(pkgName, publishId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcRefreshLNN_TEST_001
 * @tc.desc: ServerIpcRefreshLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcRefreshLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const SubscribeInfo *info = nullptr;
    int32_t ret = ServerIpcRefreshLNN(pkgName, info);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcStopRefreshLNN_TEST_001
 * @tc.desc: ServerIpcStopRefreshLNN return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcStopRefreshLNN_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    int32_t refreshId = 123;
    int32_t ret = ServerIpcStopRefreshLNN(pkgName, refreshId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcActiveMetaNode_TEST_001
 * @tc.desc: ServerIpcActiveMetaNode return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcActiveMetaNode_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const MetaNodeConfigInfo *info = nullptr;
    char testtId = 'a';
    char *metaNodeId = &testtId;
    int32_t ret = ServerIpcActiveMetaNode(pkgName, info, metaNodeId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcDeactiveMetaNode_TEST_001
 * @tc.desc: ServerIpcDeactiveMetaNode return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcDeactiveMetaNode_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *metaNodeId = "123";
    int32_t ret = ServerIpcDeactiveMetaNode(pkgName, metaNodeId);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcGetAllMetaNodeInfo_TEST_001
 * @tc.desc: ServerIpcGetAllMetaNodeInfo return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcGetAllMetaNodeInfo_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    MetaNodeInfo *infos = nullptr;
    int32_t testNum = 123;
    int32_t *infoNum = &testNum;
    int32_t ret = ServerIpcGetAllMetaNodeInfo(pkgName, infos, infoNum);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcShiftLNNGear_TEST_001
 * @tc.desc: ServerIpcShiftLNNGear return value is equal to SOFTBUS_SERVER_NOT_INIT
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcShiftLNNGear_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *callerId = "123";
    const char *targetNetworkId = "111";
    const GearMode *mode = nullptr;
    int32_t ret = ServerIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    EXPECT_EQ(ret, SOFTBUS_SERVER_NOT_INIT);
}

/*
 * @tc.name: ServerIpcSyncTrustedRelationShip_TEST_001
 * @tc.desc: ServerIpcSyncTrustedRelationShip return value is equal to SOFTBUS_TRANS_PROXY_REMOTE_NULL
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(BusCenterServerProxyTest, ServerIpcSyncTrustedRelationShip_TEST_001, TestSize.Level1)
{
    const char *pkgName = "001";
    const char *msg = "123";
    uint32_t msgLen = 123;
    int32_t ret = ServerIpcSyncTrustedRelationShip(pkgName, msg, msgLen);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_REMOTE_NULL);
}

} // namespace OHOS
