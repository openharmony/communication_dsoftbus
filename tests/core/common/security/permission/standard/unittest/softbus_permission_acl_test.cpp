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

#include "access_control.h"
#include "session.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "softbus_permission_acl_mock.h"
#include "errors.h"
#include "softbus_access_token_adapter.h"
#include "access_control_profile.h"

using namespace std;
using namespace testing::ext;
using namespace testing;
using namespace OHOS::DistributedDeviceProfile;

namespace OHOS {
const int32_t HAP_TOKENID = 123456;
const int32_t NATIVE_TOKENID = 134341184;
const pid_t NATIVE_PID = 123456;
const int32_t NATIVE_USERID = 123456;
const int32_t ERR_NOT_OK = 1;
const char APP_PKG_NAME[] = "ohos.distributedschedule.dms.connect";
constexpr char NETWORK_ID[] = "testnetworkid123";
class SoftbusPermissionACLTest : public testing::Test {
public:
    SoftbusPermissionACLTest() { }
    ~SoftbusPermissionACLTest() { }
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void TearDown() override { }
    void SetUp() override { }
};

void SoftbusPermissionACLTest::SetUpTestCase(void) { }
void SoftbusPermissionACLTest::TearDownTestCase(void) { }

/**
 * @tc.name: TransCheckClientAccessControl001
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl001, TestSize.Level0)
{
    int32_t ret = TransCheckClientAccessControl(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl002
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl002, TestSize.Level0)
{
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(TOKENID_NOT_SET));
    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl003
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl003, TestSize.Level0)
{
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACEESS_TOKEN_TYPE_INVALID));

    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl004
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl004, TestSize.Level0)
{
    bool expectedOutput = true;
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    EXPECT_CALL(mockIpc, GetCallingUid)
        .WillRepeatedly(Return(NATIVE_PID)); 

    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUid_Adapter)
        .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForeground_Adapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_NOT_OK)));
    
    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(ERR_NOT_OK, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl005
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl005, TestSize.Level0)
{
    bool expectedOutput = false;
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    EXPECT_CALL(mockIpc, GetCallingUid)
        .WillRepeatedly(Return(NATIVE_PID));

    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUid_Adapter)
        .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForeground_Adapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));

    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_TRANS_BACKGROUND_USER_DENIED, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl006
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl006, TestSize.Level0)
{
    bool expectedOutput = true;
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    EXPECT_CALL(mockIpc, GetCallingUid)
        .WillRepeatedly(Return(NATIVE_PID));

    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUid_Adapter)
        .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForeground_Adapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl007
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl007, TestSize.Level0)
{
    bool expectedOutput = true;
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    EXPECT_CALL(mockIpc, GetCallingUid)
        .WillRepeatedly(Return(NATIVE_PID)); 

    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
        .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetRemoteStrInfo)
        .WillRepeatedly(Return(SOFTBUS_ERR));
        
    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckClientAccessControl008
 * @tc.desc: test function TransCheckClientAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckClientAccessControl008, TestSize.Level0)
{
    bool expectedOutput = true;
    IPCSkeletonMock mockIpc;
    EXPECT_CALL(mockIpc, GetCallingFullTokenID)
        .WillRepeatedly(Return(HAP_TOKENID));
    EXPECT_CALL(mockIpc, GetCallingUid)
        .WillRepeatedly(Return(NATIVE_PID)); 

    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillRepeatedly(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
        .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetRemoteStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
        
    int32_t ret = TransCheckClientAccessControl(NETWORK_ID);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl001
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl001, TestSize.Level0)
{
    int32_t ret = TransCheckServerAccessControl(nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl002
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl002, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = TOKENID_NOT_SET;
    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl003
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl003, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.sessionName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl004
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl004, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.peerData.sessionName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl005
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl005, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl006
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl006, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACEESS_TOKEN_TYPE_INVALID))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_TRANS_CROSS_LAYER_DENIED, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl007
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl007, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_NATIVE))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_NATIVE));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl008
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl008, TestSize.Level0)
{
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME-1));
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl009
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl009, TestSize.Level0)
{
    bool expectedOutput = true;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME-1));
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_NOT_OK)));;

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(ERR_NOT_OK, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl010
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl010, TestSize.Level0)
{
    bool expectedOutput = false;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));;

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_TRANS_BACKGROUND_USER_DENIED, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl011
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl011, TestSize.Level0)
{
    bool expectedOutput = true;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl012
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl012, TestSize.Level0)
{
    bool expectedOutput = true;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetNetworkIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl013
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl013, TestSize.Level0)
{
    bool expectedOutput = true;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetNetworkIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetRemoteStrInfo)
        .WillRepeatedly(Return(SOFTBUS_ERR));

    int32_t ret = TransCheckServerAccessControl(&info);
    EXPECT_EQ(SOFTBUS_ERR, ret);
}

/**
 * @tc.name: TransCheckServerAccessControl014
 * @tc.desc: test function TransCheckServerAccessControl parameters.
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusPermissionACLTest, TransCheckServerAccessControl014, TestSize.Level0)
{
    bool expectedOutput = true;
    AppInfo info;
    info.callingTokenId = NATIVE_TOKENID;
    memcpy_s(info.myData.pkgName, PKG_NAME_SIZE_MAX, APP_PKG_NAME, strlen(APP_PKG_NAME)-1);
    info.peerData.userId = NATIVE_USERID;
    SoftbusPermissionACLInterfaceMock mockSPACL;
    EXPECT_CALL(mockSPACL, TransGetTokenIdBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, SoftBusGetAccessTokenType)
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP))
        .WillOnce(Return(ACCESS_TOKEN_TYPE_HAP));
    EXPECT_CALL(mockSPACL, TransProxyGetUidAndPidBySessionName)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, GetOsAccountLocalIdFromUidAdapter)
    .WillRepeatedly(Return(NATIVE_USERID));
    EXPECT_CALL(mockSPACL, IsOsAccountForegroundAdapter)
        .WillOnce(DoAll(SetArgReferee<1>(expectedOutput),
            Return(ERR_OK)));
    EXPECT_CALL(mockSPACL, LnnGetLocalStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetNetworkIdByUuid)
        .WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(mockSPACL, LnnGetRemoteStrInfo)
        .WillRepeatedly(Return(SOFTBUS_OK));

    int32_t ret = TransCheckServerAccessControl(&info);

    EXPECT_EQ(SOFTBUS_OK, ret);
}
} // namespace OHOS