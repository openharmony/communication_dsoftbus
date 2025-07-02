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

#include "iservice_registry.h"
#include "system_ability_definition.h"
#include <gtest/gtest.h>

#include "auth_log.h"
#include "disc_coap_capability_public.h"
#include "g_enhance_adapter_func.h"
#include "g_enhance_adapter_func_pack.h"
#include "g_enhance_auth_func.h"
#include "g_enhance_auth_func_pack.h"
#include "g_enhance_conn_func.h"
#include "g_enhance_conn_func_pack.h"
#include "g_enhance_disc_func.h"
#include "g_enhance_disc_func_pack.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "g_enhance_trans_func.h"
#include "g_enhance_trans_func_pack.h"
#include "lnn_heartbeat_medium_mgr.h"
#include "lnn_heartbeat_utils_struct.h"
#include "lnn_secure_storage_struct.h"
#include "softbus_broadcast_manager.h"
#include "softbus_error_code.h"
#include "softbus_init_common.h"
#include "softbus_server_frame.h"

using namespace testing;
using namespace testing::ext;

namespace OHOS {

#define TEST_SHORT_UDID_HASH_HEX_LEN 16
#define VIRTUAL_DEFAULT_SCORE 60

class SoftbusGEnhanceTest : public testing::Test {
public:
    SoftbusGEnhanceTest()
    {}
    ~SoftbusGEnhanceTest()
    {}
    static void SetUpTestCase()
    {}
    static void TearDownTestCase()
    {}
    void SetUp() override
    {}
    void TearDown() override
    {}
};

/**
 * @tc.name: SoftbusGEnhanceTest001
 * @tc.desc: AdapterRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest001, TestSize.Level1)
{
    AdapterEnhanceFuncListGet();
    int32_t ret = AdapterRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest002
 * @tc.desc: AuthRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest002, TestSize.Level1)
{
    AuthEnhanceFuncListGet();
    int32_t ret = AuthRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest003
 * @tc.desc: ConnRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest003, TestSize.Level1)
{
    ConnEnhanceFuncListGet();
    int32_t ret = ConnRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest004
 * @tc.desc: DiscRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest004, TestSize.Level1)
{
    DiscEnhanceFuncListGet();
    int32_t ret = DiscRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest005
 * @tc.desc: LnnRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest005, TestSize.Level1)
{
    LnnEnhanceFuncListGet();
    int32_t ret = LnnRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest006
 * @tc.desc: LnnRegisterEnhanceFunc function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest006, TestSize.Level1)
{
    TransEnhanceFuncListGet();
    int32_t ret = TransRegisterEnhanceFunc(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest007
 * @tc.desc: Auth function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest007, TestSize.Level1)
{
    char udidShortHash[TEST_SHORT_UDID_HASH_HEX_LEN + 1] = { 0 };
    AuthLinkType type = AUTH_LINK_TYPE_MAX;
    AuthUpdateNormalizeKeyIndexPacked(udidShortHash, 0, type, nullptr, 0);
    int32_t ret = GenerateCertificatePacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = IsNeedUDIDAbatementPacked(nullptr);
    EXPECT_EQ(ret, false);
    ret = VerifyCertificatePacked(nullptr, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    AuthMetaNotifyDataReceivedPacked(0, nullptr, nullptr);
    AuthClearDeviceKeyPacked();
    DelAuthMetaManagerByConnectionIdPacked(0);
}

/**
 * @tc.name: SoftbusGEnhanceTest008
 * @tc.desc: Conn function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest008, TestSize.Level1)
{
    int32_t ret = ConnCoapStartServerListenPacked();
    EXPECT_EQ(ret, SOFTBUS_FUNC_NOT_SUPPORT);
    ConnCoapStopServerListenPacked();
    SoftbusBleConflictNotifyDisconnectPacked(nullptr, nullptr);
    SoftbusBleConflictNotifyDateReceivePacked(0, nullptr, 0);
    SoftbusBleConflictNotifyConnectResultPacked(0, 0, 0);
    SoftbusBleConflictRegisterListenerPacked(nullptr);
    ret = ConnBleDirectInitPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    BleProtocolType protocol = BLE_PROTOCOL_MAX;
    ret = ConnBleDirectIsEnablePacked(protocol);
    EXPECT_EQ(ret, false);
    ret = ConnBleDirectConnectDevicePacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = ConnDirectConnectDevicePacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: SoftbusGEnhanceTest009
 * @tc.desc: Trans function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest009, TestSize.Level1)
{
    int32_t ret = SetDefaultQdiscPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitQosPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    NotifyQosChannelClosedPacked(0, 0);
    GetExtQosInfoPacked(nullptr, nullptr, 0, nullptr);
    ret = NotifyQosChannelOpenedPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest010
 * @tc.desc: Lnn0 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest010, TestSize.Level1)
{
    int32_t ret = AuthMetaOpenConnPacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaPostTransDataPacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    AuthMetaCloseConnPacked(0);
    ret = AuthMetaGetPreferConnInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaGetIdByConnInfoPacked(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaGetIdByUuidPacked(nullptr, AUTH_LINK_TYPE_MAX, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaEncryptPacked(0, nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaDecryptPacked(0, nullptr, 0, nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaSetP2pMacPacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaGetConnInfoPacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaGetDeviceUuidPacked(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthMetaGetServerSidePacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    AuthMetaCheckMetaExistPacked(nullptr, nullptr);
    ret = CustomizedSecurityProtocolInitPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    CustomizedSecurityProtocolDeinitPacked();
    AuthMetaDeinitPacked();
    DelAuthMetaManagerByPidPacked(nullptr, 0);
    ClearMetaNodeRequestByPidPacked(nullptr, 0);
    LnnClearAuthExchangeUdidPacked(nullptr);
    ret = AuthInsertDeviceKeyPacked(nullptr, nullptr, AUTH_LINK_TYPE_MAX);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    AuthUpdateKeyIndexPacked(nullptr, 0, 0, 0);
    ret = LnnGenerateLocalPtkPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest011
 * @tc.desc: Lnn1 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest011, TestSize.Level1)
{
    int32_t ret = CalcHKDFPacked(nullptr, 0, nullptr, 0);
    EXPECT_EQ(ret, false);
    AuthUpdateCreateTimePacked(nullptr, 0, 0);
    ret = AuthFindNormalizeKeyByServerSidePacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = IsSupportUDIDAbatementPacked();
    EXPECT_EQ(ret, false);
    ret = AuthMetaGetConnIdByInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetMetaPtkPacked(0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = PackCipherKeySyncMsgPacked(nullptr);
    EXPECT_EQ(ret, true);
    ProcessCipherKeySyncInfoPacked(nullptr, nullptr);
    FreeSoftbusChainPacked(nullptr);
    ret = InitSoftbusChainPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnSyncTrustedRelationShipPacked(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnCoapConnectPacked(nullptr);
    LnnDestroyCoapConnectListPacked();
    ret = LnnInitQosPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitQosPacked();
    ret = LnnSyncBleOfflineMsgPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnBleHbRegDataLevelChangeCbPacked(nullptr);
    LnnBleHbUnregDataLevelChangeCbPacked();
    ret = DecryptUserIdPacked(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = IsCloudSyncEnabledPacked();
    EXPECT_EQ(ret, false);
    ret = AuthFindDeviceKeyPacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = AuthFindLatestNormalizeKeyPacked(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = IsCipherManagerFindKeyPk(nullptr);
    EXPECT_EQ(ret, false);
    ret = LnnAddRemoteChannelCodePacked(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnRegistBleHeartbeatMediumMgrPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnRegisterBleLpDeviceMediumMgrPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest012
 * @tc.desc: Lnn2 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest012, TestSize.Level1)
{
    int32_t ret = HaveConcurrencyPreLinkReqIdByReuseConnReqIdPacked(0, 0);
    EXPECT_EQ(ret, false);
    ret = HaveConcurrencyPreLinkNodeByLaneReqIdPacked(0, 0);
    EXPECT_EQ(ret, false);
    ret = GetConcurrencyLaneReqIdByConnReqIdPacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnFreePreLinkPacked(nullptr);
    ret = LnnRequestCheckOnlineStatusPacked(nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnSyncPtkPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = GetConcurrencyLaneReqIdByActionIdPacked(0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = UpdateConcurrencyReuseLaneReqIdByActionIdPacked(0, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = UpdateConcurrencyReuseLaneReqIdByUdidPacked(nullptr, 0, 0);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    ret = LnnAddLocalVapInfoPacked(LNN_VAP_UNKNOWN, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnDeleteLocalVapInfoPacked(LNN_VAP_UNKNOWN);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    DisablePowerControlPacked(nullptr);
    ret = EnablePowerControlPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnInitScorePacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnStartScoringPacked(0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnInitVapInfoPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnDeinitScorePacked();
    LnnDeinitVapInfoPacked();
    ret = LnnGetWlanLinkedInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_LANE_SELECT_FAIL);
    ret = LnnGetCurrChannelScorePacked(0);
    EXPECT_EQ(ret, VIRTUAL_DEFAULT_SCORE);
    ret = IsPowerControlEnabledPacked();
    EXPECT_EQ(ret, false);
}

/**
 * @tc.name: SoftbusGEnhanceTest013
 * @tc.desc: Lnn3 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest013, TestSize.Level1)
{
    int32_t ret = LnnStartTimeSyncImplPacked(nullptr, UNAVAIL_ACCURACY, SHORT_PERIOD, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnStopTimeSyncImplPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnTimeSyncImplInitPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnTimeSyncImplDeinitPacked();
    SendDeviceStateToMlpsPacked(nullptr);
    ret = LnnRetrieveDeviceInfoByNetworkIdPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    SetLpKeepAliveStatePacked(nullptr);
    ret = LnnSetRemoteBroadcastCipherInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnGetLocalCacheNodeInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnDeleteDeviceInfoPacked(nullptr);
    ret = LnnUnPackCloudSyncDeviceInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnPackCloudSyncDeviceInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnGetLocalBroadcastCipherInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnPackCloudSyncAckSeqPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnInitCipherKeyManagerPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnSendNotTrustedInfoPacked(nullptr, 0, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    RegisterOOBEMonitorPacked(nullptr);
    ret = LnnLinkFinderInitPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: SoftbusGEnhanceTest014
 * @tc.desc: Lnn4 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest014, TestSize.Level1)
{
    int32_t ret = LnnInitFastOfflinePacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitFastOfflinePacked();
    ret = LnnRemoveLinkFinderInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnRetrieveDeviceInfoByUdidPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnInitBroadcastLinkKeyPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnInitPtkPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnDeinitBroadcastLinkKeyPacked();
    LnnDeinitPtkPacked();
    LnnIpAddrChangeEventHandlerPacked();
    LnnInitOOBEStateMonitorImplPacked();
    EhLoginEventHandlerPacked();
    ret = LnnInitMetaNodeExtLedgerPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = IsSupportLpFeaturePacked();
    EXPECT_EQ(ret, false);
    AuthLoadDeviceKeyPacked();
    ret = LnnLoadLocalDeviceInfoPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnLoadPtkInfoPacked();
    ret = LnnLoadRemoteDeviceInfoPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LoadBleBroadcastKeyPacked();
    LnnClearPtkListPacked();
    ClearDeviceInfoPacked();
    ret = GenerateNewLocalCipherKeyPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnRetrieveDeviceInfoPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnSaveRemoteDeviceInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnInsertLinkFinderInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnUpdateRemoteDeviceInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnSaveLocalDeviceInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
}

/**
 * @tc.name: SoftbusGEnhanceTest015
 * @tc.desc: Lnn5 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest015, TestSize.Level1)
{
    int32_t ret = LnnGetAccountIdFromLocalCachePacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnGetLocalDevInfoPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnGetLocalBroadcastCipherKeyPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnLoadLocalBroadcastCipherKeyPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnUpdateLocalBroadcastCipherKeyPacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = HbBuildUserIdCheckSumPacked(nullptr, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnUpdateAuthExchangeUdidPacked();
    LnnCoapConnectInitPacked();
    ret = LnnInitMetaNodePacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitActionBleConcurrencyPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = InitActionStateAdapterPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnLoadLocalDeviceAccountIdInfoPacked();
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnDeinitMetaNodePacked();
    LnnCoapConnectDeinitPacked();
    ret = LnnGetOOBEStatePacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_INVALID_PARAM);
    SoftBusOOBEState state;
    ret = LnnGetOOBEStatePacked(&state);
    EXPECT_EQ(ret, SOFTBUS_OK);
    LnnReportLaneIdStatsInfoPacked(nullptr, 0);
    ret = LnnRequestQosOptimizationPacked(nullptr, 0, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnCancelQosOptimizationPacked(nullptr, 0);
    LnnReportRippleDataPacked(0, nullptr);
    ret = LnnGetUdidByBrMacPacked(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    AuthRemoveDeviceKeyByUdidPacked(nullptr);
    ret = LnnGetRecommendChannelPacked(nullptr, nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnGetLocalPtkByUuidPacked(nullptr, nullptr, 0);
    EXPECT_EQ(ret, SOFTBUS_OK);
}

/**
 * @tc.name: SoftbusGEnhanceTest016
 * @tc.desc: Lnn6 function test
 * @tc.type: FUNC
 * @tc.require:
 */
HWTEST_F(SoftbusGEnhanceTest, SoftbusGEnhanceTest016, TestSize.Level1)
{
    int32_t ret = RegistAuthTransListenerPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = UnregistAuthTransListenerPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    ret = LnnStartRangePacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    ret = LnnStopRangePacked(nullptr);
    EXPECT_EQ(ret, SOFTBUS_NOT_IMPLEMENT);
    LnnRegSleRangeCbPacked(nullptr);
    LnnUnregSleRangeCbPacked();
    SleRangeDeathCallbackPacked();
    ret = LnnDeviceCloudConvergenceInitPacked();
    EXPECT_EQ(ret, SOFTBUS_OK);
    EXPECT_NO_FATAL_FAILURE(CheckNeedCloudSyncOfflinePacked(DISCOVERY_TYPE_BLE));
    EXPECT_NO_FATAL_FAILURE(CheckNeedCloudSyncOfflinePacked(DISCOVERY_TYPE_WIFI));
}
}