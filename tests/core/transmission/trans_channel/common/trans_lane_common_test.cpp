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

#include <cJSON.h>
#include <gtest/gtest.h>
#include <securec.h>

#include "softbus_adapter_mem.h"
#include "softbus_error_code.h"
#include "softbus_json_utils.h"
#include "trans_channel_common.c"
#include "trans_channel_common.h"
#include "trans_lane_common_test_mock.h"
#include "trans_lane_pending_ctl.c"
#include "trans_lane_pending_ctl.h"

using namespace testing;
using namespace testing::ext;

#define TEST_LEN 128
#define TEST_PID 1024
#define TEST_UID 2048
#define TEST_CHANNEL_ID 1025
#define TEST_SESSION_ID 16
#define TEST_LANE_ID 268438005
#define TEST_NEW_SESSION_ID 32
#define TEST_NEW_CHANNEL_ID 1024
#define TEST_INVALID_SESSION_ID (-1)

namespace OHOS {
static constexpr char *TEST_IP = "192.168.1.111";
static constexpr char *TEST_NEW_WORK_ID = "ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00ABCDEF00";
static constexpr char *TEST_INFO = "test";
static constexpr char *TEST_ID = "testId";
static constexpr char *TEST_DEVICEVERSION = "testDevicersion";
static constexpr char *TEST_FAST_TRANS_DATA = "testFastTransData";
static constexpr char *TEST_SESSION_NAME = "ohos.distributedschedule.dms.test";
static constexpr char *TEST_PEER_SESSION_NAME = "test.ohos.distributedschedule.dms.test";
static constexpr char *TEST_INVALID_SESSION_NAME = "ohos.distributedschedule.dms.test.ohos.distributedschedule.\
    dms.test.ohos.distributedschedule.dms.test.ohos.distributedschedule.dms.test.ohos.distributedschedule.dms.\
    test.ohos.distributedschedule.dms.test.ohos.distributedschedule.dms.test.ohos.distributedschedule.dms.test";
static constexpr char *TEST_DEVICE_ID = "ABCDEF00ABCDEF00ABCDEF00";
static constexpr char *TEST_GROUP_ID = "TEST_GROUP_ID";
static constexpr char *TEST_PKG_NAME = "testPkgName";

class TransLaneCommonTest : public testing::Test {
public:
    TransLaneCommonTest()
    {}
    ~TransLaneCommonTest()
    {}
    static void SetUpTestCase(void);
    static void TearDownTestCase(void);
    void SetUp() override
    {}
    void TearDown() override
    {}
};

void TransLaneCommonTest::SetUpTestCase(void)
{
}

void TransLaneCommonTest::TearDownTestCase(void)
{
}

static AppInfo *TestCreateAppInfo()
{
    AppInfo *appInfo = (AppInfo *)SoftBusCalloc(sizeof(AppInfo));
    if (appInfo == nullptr) {
        return nullptr;
    }

    appInfo->businessType = BUSINESS_TYPE_FILE;
    appInfo->myData.uid = TEST_UID;
    appInfo->myData.pid = TEST_PID;

    return appInfo;
}

static SessionParam *TestCreateSessionParam()
{
    SessionAttribute *attr = (SessionAttribute *)SoftBusCalloc(sizeof(SessionAttribute));
    if (attr == nullptr) {
        return nullptr;
    }

    attr->fastTransData = const_cast<uint8_t *>(TEST_FAST_TRANS_DATA);
    attr->fastTransDataSize = TEST_LEN;

    SessionParam *param = (SessionParam *)SoftBusCalloc(sizeof(SessionParam));
    if (param == nullptr) {
        SoftBusFree(attr);
        return nullptr;
    }

    param->attr = attr;

    return param;
}

static int32_t GetLocalIpByRemoteIp(const char *remoteIp, char *localIp, int32_t localIpSize)
{
    (void)remoteIp;
    (void)localIp;
    (void)localIpSize;
    return SOFTBUS_INVALID_PARAM;
}

/**
 * @tc.name: TransCommonGetLocalConfig001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when len is nullptr
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR when SoftbusGetConfig return unequal SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransCommonGetLocalConfig001, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    int32_t businessType = BUSINESS_TYPE_BYTE;
    uint32_t len = TEST_LEN;

    int32_t ret = TransCommonGetLocalConfig(channelType, businessType, nullptr);
    EXPECT_EQ(SOFTBUS_INVALID_PARAM, ret);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, SoftbusGetConfig).WillOnce(Return(SOFTBUS_INVALID_PARAM));
    ret = TransCommonGetLocalConfig(channelType, businessType, &len);
    EXPECT_EQ(SOFTBUS_GET_CONFIG_VAL_ERR, ret);
}

/**
 * @tc.name: TransGetChannelType001
 * @tc.desc: Should return different value when given different valid param
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR when SoftbusGetConfig return unequal SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransGetChannelType001, TestSize.Level1)
{
    int32_t type = LANE_BR;
    int32_t ret = TransGetChannelType(nullptr, type);
    EXPECT_EQ(CHANNEL_TYPE_BUTT, ret);

    SessionAttribute attr;
    attr.dataType = TYPE_FILE;
    SessionParam fileParam = {
        .attr = &attr,
    };

    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);

    type = LANE_BLE;
    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);

    type = LANE_BLE_DIRECT;
    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);

    type = LANE_COC;
    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);

    type = LANE_COC_DIRECT;
    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);

    type = LANE_P2P;
    ret = TransGetChannelType(&fileParam, type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, ret);

    attr.dataType = TYPE_MESSAGE;
    SessionParam MsgParam = {
        .attr = &attr,
    };

    ret = TransGetChannelType(&MsgParam, type);
    EXPECT_EQ(CHANNEL_TYPE_TCP_DIRECT, ret);

    type = LANE_P2P_REUSE;
    ret = TransGetChannelType(&MsgParam, type);
    EXPECT_EQ(CHANNEL_TYPE_TCP_DIRECT, ret);

    type = LANE_HML;
    ret = TransGetChannelType(&MsgParam, type);
    EXPECT_EQ(CHANNEL_TYPE_TCP_DIRECT, ret);

    type = LANE_WLAN_5G;
    ret = TransGetChannelType(&MsgParam, type);
    EXPECT_EQ(CHANNEL_TYPE_PROXY, ret);
}

/**
 * @tc.name: TransGetChannelType002
 * @tc.desc: Should return different value when given different valid param
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR when SoftbusGetConfig return unequal SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransGetChannelType002, TestSize.Level1)
{
    int32_t type = LANE_P2P;

    SessionAttribute attr;
    attr.dataType = TYPE_STREAM;
    attr.attr.streamAttr.streamType = RAW_STREAM;
    SessionParam rawParam = {
        .attr = &attr,
    };

    int32_t ret = TransGetChannelType(&rawParam, type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, ret);

    attr.attr.streamAttr.streamType = COMMON_VIDEO_STREAM;
    SessionParam videoParam = {
        .attr = &attr,
    };

    ret = TransGetChannelType(&videoParam, type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, ret);

    attr.attr.streamAttr.streamType = COMMON_AUDIO_STREAM;
    SessionParam audioParam = {
        .attr = &attr,
    };

    ret = TransGetChannelType(&audioParam, type);
    EXPECT_EQ(CHANNEL_TYPE_UDP, ret);
}

/**
 * @tc.name: FillAppInfo001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when len is nullptr
 * @tc.desc: Should return SOFTBUS_GET_CONFIG_VAL_ERR when SoftbusGetConfig return unequal SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, FillAppInfo001, TestSize.Level1)
{
    AppInfo appInfo;
    TransInfo transInfo;
    LaneConnInfo connInfo;
    SessionAttribute attr;

    attr.dataType = TYPE_BYTES;
    SessionParam param = {
        .attr = &attr,
    };

    FillAppInfo(nullptr, &param, &transInfo, &connInfo);
    FillAppInfo(&appInfo, nullptr, &transInfo, &connInfo);
    FillAppInfo(&appInfo, &param, nullptr, &connInfo);
    FillAppInfo(&appInfo, &param, &transInfo, nullptr);

    (void)strcpy_s(connInfo.connInfo.p2p.localIp, IP_LEN, TEST_IP);
    connInfo.type = LANE_HML;

    appInfo.businessType = BUSINESS_TYPE_BYTE;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, SoftbusGetConfig).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    FillAppInfo(&appInfo, &param, &transInfo, &connInfo);

    connInfo.type = LANE_P2P;
    FillAppInfo(&appInfo, &param, &transInfo, &connInfo);
    EXPECT_EQ(appInfo.linkType, connInfo.type);

    WifiDirectManager mgr = {
        .getLocalIpByRemoteIp = GetLocalIpByRemoteIp,
    };
    EXPECT_CALL(TransLaneCommonMock, GetWifiDirectManager).WillOnce(Return(nullptr));
    connInfo.type = LANE_P2P_REUSE;
    FillAppInfo(&appInfo, &param, &transInfo, &connInfo);
    EXPECT_EQ(appInfo.linkType, connInfo.type);

    EXPECT_CALL(TransLaneCommonMock, GetWifiDirectManager).WillOnce(Return(&mgr));
    FillAppInfo(&appInfo, &param, &transInfo, &connInfo);
    EXPECT_EQ(appInfo.linkType, connInfo.type);
}

/**
 * @tc.name: GetOsTypeByNetworkId001
 * @tc.desc: Test GetOsTypeByNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, GetOsTypeByNetworkId001, TestSize.Level1)
{
    int32_t osType = 1;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    GetOsTypeByNetworkId(TEST_NEW_WORK_ID, &osType);
    EXPECT_EQ(osType, 1);

    EXPECT_CALL(TransLaneCommonMock, LnnGetOsTypeByNetworkId).WillRepeatedly(Return(SOFTBUS_OK));
    GetOsTypeByNetworkId(TEST_NEW_WORK_ID, &osType);
    EXPECT_EQ(osType, 1);
}

/**
 * @tc.name: GetRemoteUdidWithNetworkId001
 * @tc.desc: Test GetRemoteUdidWithNetworkId
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, GetRemoteUdidWithNetworkId001, TestSize.Level1)
{
    char udid[DEVICE_ID_SIZE_MAX] = {0};
    uint32_t len = DEVICE_ID_SIZE_MAX;

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    GetRemoteUdidWithNetworkId(TEST_NEW_WORK_ID, udid, len);
    EXPECT_EQ(strlen(udid), 0);

    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    GetRemoteUdidWithNetworkId(TEST_NEW_WORK_ID, udid, len);
    EXPECT_EQ(strlen(udid), 0);
}

/**
 * @tc.name: TransGetRemoteDeviceVersion001
 * @tc.desc: Test TransGetRemoteDeviceVersion
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransGetRemoteDeviceVersion001, TestSize.Level1)
{
    IdCategory type = CATEGORY_UDID;
    char deviceVersion[DEVICE_VERSION_SIZE_MAX] = {0};
    uint32_t len = DEVICE_VERSION_SIZE_MAX;
    TransGetRemoteDeviceVersion(nullptr, type, deviceVersion, len);
    EXPECT_EQ(strlen(deviceVersion), 0);
    
    TransGetRemoteDeviceVersion(TEST_ID, type, nullptr, len);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteNodeInfoById).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    TransGetRemoteDeviceVersion(TEST_ID, type, deviceVersion, len);
    EXPECT_EQ(strlen(deviceVersion), 0);
}

/**
 * @tc.name: CopyAppInfoFromSessionParam001
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when param or param->attr is nullptr
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, CopyAppInfoFromSessionParam001, TestSize.Level1)
{
    AppInfo appInfo;
    SessionParam testParam = {
        .attr = nullptr,
    };

    int32_t ret = CopyAppInfoFromSessionParam(&appInfo, nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    ret = CopyAppInfoFromSessionParam(&appInfo, &testParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: CopyAppInfoFromSessionParam002
 * @tc.desc: Should return SOFTBUS_INVALID_PARAM when TransGetUidAndPid return SOFTBUS_INVALID_PARAM
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, CopyAppInfoFromSessionParam002, TestSize.Level1)
{
    AppInfo appInfo;
    SessionAttribute attr;
    attr.fastTransData = nullptr;
    SessionParam Param = {
        .attr = &attr,
    };

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_INVALID_PARAM));
    int32_t ret = CopyAppInfoFromSessionParam(&appInfo, &Param);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SessionAttribute testAttr;
    testAttr.fastTransData = const_cast<uint8_t *>(TEST_FAST_TRANS_DATA);
    testAttr.fastTransDataSize = -1;
    SessionParam testParam = {
        .attr = &testAttr,
    };
    ret = CopyAppInfoFromSessionParam(&appInfo, &testParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);

    SessionAttribute newAttr;
    newAttr.fastTransDataSize = MAX_FAST_DATA_LEN + 1;
    SessionParam newParam = {
        .attr = &newAttr,
    };

    ret = CopyAppInfoFromSessionParam(&appInfo, &newParam);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
}

/**
 * @tc.name: CopyAppInfoFromSessionParam003
 * @tc.desc: Should return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH when businessType is BUSINESS_TYPE_FILE
 * @tc.desc: Should return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH when businessType is BUSINESS_TYPE_STREAM
 * @tc.desc: Should return SOFTBUS_MEM_ERR when groupId or sessionName or peerDeviceId or peerSessionName is nullptr
 * @tc.desc: Should return SOFTBUS_TRANS_BAD_KEY when TransGetPkgNameBySessionName return SOFTBUS_TRANS_BAD_KEY
 * @tc.desc: Should return SOFTBUS_TRANS_BAD_KEY when TransGetPkgNameBySessionName return LnnGetRemoteStrInfo
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, CopyAppInfoFromSessionParam003, TestSize.Level1)
{
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_NE(appInfo, nullptr);

    SessionParam *param = TestCreateSessionParam();
    EXPECT_NE(param, nullptr);

    appInfo->businessType = BUSINESS_TYPE_FILE;
    int32_t ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH);

    appInfo->businessType = BUSINESS_TYPE_STREAM;
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    param->groupId = TEST_GROUP_ID;
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    param->sessionName = TEST_SESSION_NAME;
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_TRANS_BAD_KEY));
    param->peerDeviceId = TEST_DEVICE_ID;
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_MEM_ERR);

    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillOnce(Return(SOFTBUS_TRANS_BAD_KEY));
    param->peerSessionName = TEST_PEER_SESSION_NAME;
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_TRANS_BAD_KEY));
    ret = CopyAppInfoFromSessionParam(appInfo, param);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
    SoftBusFree(param->attr);
    SoftBusFree(param);
}

/**
 * @tc.name: TransCommonGetAppInfo001
 * @tc.desc: Should return SOFTBUS_TRANS_BAD_KEY when LnnGetLocalStrInfo return SOFTBUS_TRANS_BAD_KEY
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransCommonGetAppInfo001, TestSize.Level1)
{
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_NE(appInfo, nullptr);

    SessionParam *param = TestCreateSessionParam();
    EXPECT_NE(param, nullptr);

    param->peerDeviceId = TEST_DEVICE_ID;
    SessionAttribute attr = {
        attr.dataType = TYPE_STREAM,
        attr.attr.streamAttr.streamType = 1,
    };
    param->attr = &attr;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    int32_t ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    SessionAttribute testAttr = {
        attr.dataType = TYPE_FILE,
    };
    param->attr = &testAttr;
    ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    SessionAttribute newAttr = {
        attr.dataType = TYPE_MESSAGE,
    };
    param->attr = &newAttr;
    ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    SessionAttribute testNewAttr = {
        attr.dataType = TYPE_BYTES,
    };
    param->attr = &testNewAttr;
    ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BAD_KEY);

    SoftBusFree(appInfo);
    SoftBusFree(param->attr);
    SoftBusFree(param);
}

/**
 * @tc.name: TransCommonGetAppInfo002
 * @tc.desc: Should return SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH when businessType is BUSINESS_TYPE_FILE
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransCommonGetAppInfo002, TestSize.Level1)
{
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_NE(appInfo, nullptr);

    SessionParam *param = TestCreateSessionParam();
    EXPECT_NE(param, nullptr);

    param->peerDeviceId = TEST_DEVICE_ID;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    int32_t ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH);

    appInfo->businessType = BUSINESS_TYPE_BYTE;
    param->groupId = TEST_GROUP_ID;
    param->sessionName = TEST_SESSION_NAME;
    param->peerDeviceId = TEST_DEVICE_ID;
    param->peerSessionName = TEST_PEER_SESSION_NAME;
    EXPECT_CALL(TransLaneCommonMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetOsTypeByNetworkId).WillOnce(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetRemoteNodeInfoById).WillOnce(Return(SOFTBUS_TRANS_BAD_KEY));
    ret = TransCommonGetAppInfo(param, appInfo);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
    SoftBusFree(param->attr);
    SoftBusFree(param);
}

/**
 * @tc.name: TransOpenChannelSetModule001
 * @tc.desc: test TransOpenChannelSetModule
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransOpenChannelSetModule001, TestSize.Level1)
{
    int32_t channelType = CHANNEL_TYPE_PROXY;
    ConnectOption connOpt = {
        .socketOption.protocol = LNN_PROTOCOL_VTP,
        .type = CONNECT_BR,
    };
    TransOpenChannelSetModule(channelType, &connOpt);

    connOpt.type = CONNECT_TCP;
    TransOpenChannelSetModule(channelType, &connOpt);

    connOpt.socketOption.protocol = LNN_PROTOCOL_NIP;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetProtocolListenerModule).WillRepeatedly(Return(LANE));
    TransOpenChannelSetModule(channelType, &connOpt);
    EXPECT_EQ(connOpt.socketOption.moduleId, LANE);

    channelType = CHANNEL_TYPE_TCP_DIRECT;
    TransOpenChannelSetModule(channelType, &connOpt);
    EXPECT_EQ(connOpt.socketOption.moduleId, LANE);
}

/**
 * @tc.name: TransOpenChannelProc001
 * @tc.desc: Should return SOFTBUS_INVALID_NUM when TransOpenUdpChannel return SOFTBUS_INVALID_NUM
 * @tc.desc: Should return SOFTBUS_INVALID_NUM when TransProxyOpenProxyChannel return SOFTBUS_INVALID_NUM
 * @tc.desc: Should return SOFTBUS_INVALID_NUM when TransOpenDirectChannel return SOFTBUS_INVALID_NUM
 * @tc.desc: Should return SOFTBUS_OK when TransOpenDirectChannel return SOFTBUS_OK
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransOpenChannelProc001, TestSize.Level1)
{
    ChannelType type = CHANNEL_TYPE_BUTT;
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_NE(appInfo, nullptr);

    ConnectOption connOpt;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t ret = TransOpenChannelProc(type, appInfo, &connOpt, &channelId);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_CHANNEL_TYPE);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransOpenUdpChannel).WillOnce(Return(SOFTBUS_INVALID_NUM));
    type = CHANNEL_TYPE_UDP;
    ret = TransOpenChannelProc(type, appInfo, &connOpt, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_NUM);

    EXPECT_CALL(TransLaneCommonMock, TransProxyOpenProxyChannel).WillOnce(Return(SOFTBUS_INVALID_NUM));
    type = CHANNEL_TYPE_PROXY;
    ret = TransOpenChannelProc(type, appInfo, &connOpt, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_NUM);

    EXPECT_CALL(TransLaneCommonMock, TransOpenDirectChannel).WillOnce(Return(SOFTBUS_INVALID_NUM));
    type = CHANNEL_TYPE_TCP_DIRECT;
    ret = TransOpenChannelProc(type, appInfo, &connOpt, &channelId);
    EXPECT_EQ(ret, SOFTBUS_INVALID_NUM);

    EXPECT_CALL(TransLaneCommonMock, TransOpenDirectChannel).WillOnce(Return(SOFTBUS_OK));
    ret = TransOpenChannelProc(type, appInfo, &connOpt, &channelId);
    EXPECT_EQ(ret, SOFTBUS_OK);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: CancelWaitLaneState001
 * @tc.desc: Should return SOFTBUS_TRANS_INVALID_SESSION_ID when given invalid param
 * @tc.desc: Should return SOFTBUS_OK when given valid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, CancelWaitLaneState001, TestSize.Level1)
{
    uint32_t laneHandle = TEST_LANE_ID;
    bool isQosLane = true;
    bool isAsync = true;
    int32_t channelId = TEST_CHANNEL_ID;
    int32_t channelType = CHANNEL_TYPE_TCP_DIRECT;
    CoreSessionState state = CORE_SESSION_STATE_WAIT_LANE;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));

    int32_t ret = CancelWaitLaneState(TEST_SESSION_NAME, TEST_INVALID_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_TRANS_INVALID_SESSION_ID);

    ret = TransSocketLaneMgrInit();
    EXPECT_EQ(ret, SOFTBUS_OK);

    // will delete in CancelWaitLaneState
    ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID, channelId, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channelId = TEST_NEW_CHANNEL_ID;
    // will delete in CancelWaitLaneState
    ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_NEW_SESSION_ID, channelId, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransUpdateSocketChannelLaneInfoBySession(TEST_SESSION_NAME, TEST_SESSION_ID,
        laneHandle, isQosLane, isAsync);
    EXPECT_EQ(ret, SOFTBUS_OK);

    isAsync = false;
    ret = TransUpdateSocketChannelLaneInfoBySession(TEST_SESSION_NAME, TEST_NEW_SESSION_ID,
        laneHandle, isQosLane, isAsync);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = CancelWaitLaneState(TEST_SESSION_NAME, TEST_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = CancelWaitLaneState(TEST_SESSION_NAME, TEST_NEW_SESSION_ID);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: TransCommonCloseChannel001
 * @tc.desc: Should return SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID when given invalid param
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransCommonCloseChannel001, TestSize.Level1)
{
    int32_t channelId = TEST_CHANNEL_ID;
    CoreSessionState state = CORE_SESSION_STATE_WAIT_LANE;
    int32_t channelType = CHANNEL_TYPE_UNDEFINED;
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransGetUidAndPid).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));

    // will delete in TransCommonCloseChannel
    int32_t ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_SESSION_ID, channelId, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);

    ret = TransCommonCloseChannel(TEST_SESSION_NAME, channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_NOT_FIND);
    ret = TransCommonCloseChannel(TEST_SESSION_NAME, TEST_SESSION_ID, channelType);
    EXPECT_EQ(ret, SOFTBUS_OK);

    channelType = CHANNEL_TYPE_PROXY;
    // will delete in TransCommonCloseChannel
    ret = TransAddSocketChannelInfo(TEST_SESSION_NAME, TEST_NEW_SESSION_ID, channelId, channelType, state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = TransCommonCloseChannel(TEST_SESSION_NAME, channelId, channelType);
    EXPECT_EQ(ret, SOFTBUS_TRANS_PROXY_INVALID_CHANNEL_ID);
}

/**
 * @tc.name: TransBuildTransOpenChannelStartEvent001
 * @tc.desc: test TransBuildTransOpenChannelStartEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransBuildTransOpenChannelStartEvent001, TestSize.Level1)
{
    TransEventExtra extra;
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_NE(appInfo, nullptr);
    NodeInfo nodeInfo;
    (void)memcpy_s(nodeInfo.masterUdid, TEST_LEN, TEST_IP, TEST_LEN);
    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    int32_t peerRet = SOFTBUS_OK;
    TransBuildTransOpenChannelStartEvent(nullptr, appInfo, &nodeInfo, peerRet);
    EXPECT_EQ(extra.result, SOFTBUS_OK);

    TransBuildTransOpenChannelStartEvent(&extra, nullptr, &nodeInfo, peerRet);
    EXPECT_EQ(extra.result, SOFTBUS_OK);

    TransBuildTransOpenChannelStartEvent(&extra, appInfo, nullptr, peerRet);
    EXPECT_EQ(extra.result, SOFTBUS_OK);

    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    TransBuildTransOpenChannelStartEvent(&extra, appInfo, &nodeInfo, peerRet);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_OK));
    TransBuildTransOpenChannelStartEvent(&extra, appInfo, &nodeInfo, peerRet);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    SoftBusFree(appInfo);
}

/**
 * @tc.name: TransBuildOpenAuthChannelStartEvent001
 * @tc.desc: test TransBuildOpenAuthChannelStartEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransBuildOpenAuthChannelStartEvent001, TestSize.Level1)
{
    TransEventExtra extra;
    ConnectOption connOpt = {
        .type = CONNECT_BR,
    };
    char *localUdid = const_cast<char *>(TEST_IP);
    char *callerPkg = const_cast<char *>(TEST_PKG_NAME);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_INVALID_SESSION_NAME, &connOpt, localUdid, callerPkg);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildOpenAuthChannelStartEvent(nullptr, TEST_SESSION_NAME, &connOpt, localUdid, callerPkg);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_SESSION_NAME, nullptr, localUdid, callerPkg);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_SESSION_NAME, &connOpt, nullptr, callerPkg);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_SESSION_NAME, &connOpt, localUdid, nullptr);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    NiceMock<TransLaneCommonTestInterfaceMock> TransLaneCommonMock;
    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_SESSION_NAME, &connOpt, localUdid, callerPkg);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    EXPECT_CALL(TransLaneCommonMock, TransGetPkgNameBySessionName).WillRepeatedly(Return(SOFTBUS_OK));
    EXPECT_CALL(TransLaneCommonMock, LnnGetLocalStrInfo).WillRepeatedly(Return(SOFTBUS_TRANS_BAD_KEY));
    TransBuildOpenAuthChannelStartEvent(&extra, TEST_SESSION_NAME, &connOpt, localUdid, callerPkg);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);
}

/**
 * @tc.name: TransBuildTransOpenChannelCancelEvent001
 * @tc.desc: test TransBuildTransOpenChannelCancelEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransBuildTransOpenChannelCancelEvent001, TestSize.Level1)
{
    TransEventExtra extra;
    TransInfo transInfo = {
        .channelId = TEST_CHANNEL_ID,
    };

    int64_t timeStart = 0;
    int32_t ret = SOFTBUS_OK;
    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildTransOpenChannelCancelEvent(&extra, &transInfo, timeStart, ret);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_CANCELED);

    TransBuildTransOpenChannelCancelEvent(nullptr, &transInfo, timeStart, ret);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildTransOpenChannelCancelEvent(&extra, nullptr, timeStart, ret);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);
}

/**
 * @tc.name: TransBuildTransOpenChannelEndEvent001
 * @tc.desc: test TransBuildTransOpenChannelEndEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransBuildTransOpenChannelEndEvent001, TestSize.Level1)
{
    TransEventExtra extra;
    TransInfo transInfo = {
        .channelId = TEST_CHANNEL_ID,
    };
    int64_t timeStart = 0;
    int32_t ret = SOFTBUS_OK;

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildTransOpenChannelEndEvent(&extra, &transInfo, timeStart, ret);
    EXPECT_EQ(extra.result, EVENT_STAGE_RESULT_OK);

    TransBuildTransOpenChannelEndEvent(nullptr, &transInfo, timeStart, ret);

    (void)memset_s(&extra, sizeof(extra), 0, sizeof(extra));
    TransBuildTransOpenChannelEndEvent(&extra, nullptr, timeStart, ret);
    EXPECT_NE(extra.result, EVENT_STAGE_RESULT_OK);
}

/**
 * @tc.name: TransBuildTransAlarmEvent001
 * @tc.desc: test TransBuildTransAlarmEvent
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(TransLaneCommonTest, TransBuildTransAlarmEvent001, TestSize.Level1)
{
    TransAlarmExtra extraAlarm;
    AppInfo *appInfo = TestCreateAppInfo();
    EXPECT_EQ(appInfo, nullptr);

    (void)memcpy_s(appInfo->myData.sessionName, TEST_LEN, TEST_SESSION_NAME, TEST_LEN);
    (void)memset_s(&extraAlarm, sizeof(extraAlarm), 0, sizeof(extraAlarm));
    int32_t ret = SOFTBUS_OK;

    TransBuildTransAlarmEvent(&extraAlarm, appInfo, ret);
    EXPECT_EQ(extraAlarm.errcode, SOFTBUS_OK);

    TransBuildTransAlarmEvent(nullptr, appInfo, ret);

    extraAlarm.errcode = SOFTBUS_TRANS_BAD_KEY;
    TransBuildTransAlarmEvent(&extraAlarm, nullptr, ret);
    EXPECT_EQ(extraAlarm.errcode, SOFTBUS_TRANS_BAD_KEY);

    SoftBusFree(appInfo);
}
} // namespace OHOS
