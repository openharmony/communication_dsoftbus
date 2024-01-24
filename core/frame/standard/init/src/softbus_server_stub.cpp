/*
 * Copyright (c) 2021-2023 Huawei Device Co., Ltd.
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

#include "softbus_server_stub.h"

#include "accesstoken_kit.h"
#include "access_control.h"
#include "access_token.h"
#include "anonymizer.h"
#include "comm_log.h"
#include "discovery_service.h"
#include "ipc_skeleton.h"
#include "ipc_types.h"
#include "privacy_kit.h"
#include "regex.h"
#include "securec.h"
#include "softbus_adapter_mem.h"
#include "softbus_bus_center.h"
#include "softbus_conn_interface.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_server_ipc_interface_code.h"
#include "softbus_permission.h"
#include "softbus_server.h"
#include "softbus_server_frame.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_session_manager.h"

#ifdef SUPPORT_BUNDLENAME
#include "bundle_mgr_interface.h"
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif

#define JUDG_CNT 1
using namespace OHOS::Security::AccessToken;

namespace OHOS {
int32_t SoftBusServerStub::CheckOpenSessionPermission(const SessionParam *param)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    if ((param == nullptr) ||
        (TransGetPkgNameBySessionName(param->sessionName, pkgName, PKG_NAME_SIZE_MAX) != SOFTBUS_OK)) {
        COMM_LOGE(COMM_SVC, "OpenSession pararm error or lock mutex or copy pkgName failed");
        return SOFTBUS_INVALID_PARAM;
    }

    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, param->sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "OpenSession no permission");
        return SOFTBUS_PERMISSION_DENIED;
    }

    if (CheckTransSecLevel(param->sessionName, param->peerSessionName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "OpenSession sec level invalid");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CheckChannelPermission(int32_t channelId, int32_t channelType)
{
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    char sessionName[SESSION_NAME_SIZE_MAX] = {0};
    int32_t ret = SOFTBUS_OK;
    TransInfo info;
    info.channelId = channelId;
    info.channelType = channelType;
    ret = TransGetNameByChanId(&info, pkgName, sessionName, PKG_NAME_SIZE_MAX, SESSION_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "ServerCloseChannel invalid channel info");
        return ret;
    }

    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_OPEN) != SOFTBUS_OK) {
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

static inline int32_t CheckAndRecordAccessToken(const char* permission)
{
    uint32_t tokenCaller = IPCSkeleton::GetCallingTokenID();
    int32_t ret = AccessTokenKit::VerifyAccessToken(tokenCaller, permission);

    ATokenTypeEnum type = AccessTokenKit::GetTokenTypeFlag(tokenCaller);
    int32_t successCnt = (int32_t)(ret == PERMISSION_GRANTED);
    int32_t failCnt = JUDG_CNT - successCnt;
    if (type == TOKEN_HAP) {
        PrivacyKit::AddPermissionUsedRecord(tokenCaller, permission, successCnt, failCnt);
    }
    return ret;
}

static inline void SoftbusReportPermissionFaultEvt(uint32_t ipcCode)
{
    if (ipcCode == SERVER_OPEN_SESSION) {
        SoftbusReportTransErrorEvt(SOFTBUS_ACCESS_TOKEN_DENIED);
    }
}

SoftBusServerStub::SoftBusServerStub()
{
    InitMemberFuncMap();
    InitMemberPermissionMap();
}

void SoftBusServerStub::InitMemberFuncMap()
{
    memberFuncMap_[SERVER_START_DISCOVERY] = &SoftBusServerStub::StartDiscoveryInner;
    memberFuncMap_[SERVER_STOP_DISCOVERY] = &SoftBusServerStub::StopDiscoveryInner;
    memberFuncMap_[SERVER_PUBLISH_SERVICE] = &SoftBusServerStub::PublishServiceInner;
    memberFuncMap_[SERVER_UNPUBLISH_SERVICE] = &SoftBusServerStub::UnpublishServiceInner;
    memberFuncMap_[MANAGE_REGISTER_SERVICE] = &SoftBusServerStub::SoftbusRegisterServiceInner;
    memberFuncMap_[SERVER_CREATE_SESSION_SERVER] = &SoftBusServerStub::CreateSessionServerInner;
    memberFuncMap_[SERVER_REMOVE_SESSION_SERVER] = &SoftBusServerStub::RemoveSessionServerInner;
    memberFuncMap_[SERVER_OPEN_SESSION] = &SoftBusServerStub::OpenSessionInner;
    memberFuncMap_[SERVER_OPEN_AUTH_SESSION] = &SoftBusServerStub::OpenAuthSessionInner;
    memberFuncMap_[SERVER_NOTIFY_AUTH_SUCCESS] = &SoftBusServerStub::NotifyAuthSuccessInner;
    memberFuncMap_[SERVER_CLOSE_CHANNEL] = &SoftBusServerStub::CloseChannelInner;
    memberFuncMap_[SERVER_SESSION_SENDMSG] = &SoftBusServerStub::SendMessageInner;
    memberFuncMap_[SERVER_EVALUATE_QOS] = &SoftBusServerStub::EvaluateQosInner;
    memberFuncMap_[SERVER_JOIN_LNN] = &SoftBusServerStub::JoinLNNInner;
    memberFuncMap_[SERVER_LEAVE_LNN] = &SoftBusServerStub::LeaveLNNInner;
    memberFuncMap_[SERVER_GET_ALL_ONLINE_NODE_INFO] = &SoftBusServerStub::GetAllOnlineNodeInfoInner;
    memberFuncMap_[SERVER_GET_LOCAL_DEVICE_INFO] = &SoftBusServerStub::GetLocalDeviceInfoInner;
    memberFuncMap_[SERVER_GET_NODE_KEY_INFO] = &SoftBusServerStub::GetNodeKeyInfoInner;
    memberFuncMap_[SERVER_SET_NODE_DATA_CHANGE_FLAG] = &SoftBusServerStub::SetNodeDataChangeFlagInner;
    memberFuncMap_[SERVER_START_TIME_SYNC] = &SoftBusServerStub::StartTimeSyncInner;
    memberFuncMap_[SERVER_STOP_TIME_SYNC] = &SoftBusServerStub::StopTimeSyncInner;
    memberFuncMap_[SERVER_QOS_REPORT] = &SoftBusServerStub::QosReportInner;
    memberFuncMap_[SERVER_STREAM_STATS] = &SoftBusServerStub::StreamStatsInner;
    memberFuncMap_[SERVER_GRANT_PERMISSION] = &SoftBusServerStub::GrantPermissionInner;
    memberFuncMap_[SERVER_REMOVE_PERMISSION] = &SoftBusServerStub::RemovePermissionInner;
    memberFuncMap_[SERVER_PUBLISH_LNN] = &SoftBusServerStub::PublishLNNInner;
    memberFuncMap_[SERVER_STOP_PUBLISH_LNN] = &SoftBusServerStub::StopPublishLNNInner;
    memberFuncMap_[SERVER_REFRESH_LNN] = &SoftBusServerStub::RefreshLNNInner;
    memberFuncMap_[SERVER_STOP_REFRESH_LNN] = &SoftBusServerStub::StopRefreshLNNInner;
    memberFuncMap_[SERVER_ACTIVE_META_NODE] = &SoftBusServerStub::ActiveMetaNodeInner;
    memberFuncMap_[SERVER_DEACTIVE_META_NODE] = &SoftBusServerStub::DeactiveMetaNodeInner;
    memberFuncMap_[SERVER_GET_ALL_META_NODE_INFO] = &SoftBusServerStub::GetAllMetaNodeInfoInner;
    memberFuncMap_[SERVER_SHIFT_LNN_GEAR] = &SoftBusServerStub::ShiftLNNGearInner;
    memberFuncMap_[SERVER_RIPPLE_STATS] = &SoftBusServerStub::RippleStatsInner;
    memberFuncMap_[SERVER_GET_SOFTBUS_SPEC_OBJECT] = &SoftBusServerStub::GetSoftbusSpecObjectInner;
    memberFuncMap_[SERVER_GET_BUS_CENTER_EX_OBJ] = &SoftBusServerStub::GetBusCenterExObjInner;
}

void SoftBusServerStub::InitMemberPermissionMap()
{
    memberPermissionMap_[SERVER_START_DISCOVERY] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_DISCOVERY] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_PUBLISH_SERVICE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_UNPUBLISH_SERVICE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[MANAGE_REGISTER_SERVICE] = nullptr;
    memberPermissionMap_[SERVER_CREATE_SESSION_SERVER] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_REMOVE_SESSION_SERVER] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_OPEN_SESSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_OPEN_AUTH_SESSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_NOTIFY_AUTH_SUCCESS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_CLOSE_CHANNEL] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_SESSION_SENDMSG] = nullptr;
    memberPermissionMap_[SERVER_JOIN_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_JOIN_METANODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_LEAVE_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_LEAVE_METANODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_GET_ALL_ONLINE_NODE_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_LOCAL_DEVICE_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_NODE_KEY_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_SET_NODE_DATA_CHANGE_FLAG] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_START_TIME_SYNC] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_TIME_SYNC] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_QOS_REPORT] = nullptr;
    memberPermissionMap_[SERVER_STREAM_STATS] = nullptr;
    memberPermissionMap_[SERVER_GRANT_PERMISSION] = nullptr;
    memberPermissionMap_[SERVER_REMOVE_PERMISSION] = nullptr;
    memberPermissionMap_[SERVER_PUBLISH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_PUBLISH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_REFRESH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_REFRESH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_ACTIVE_META_NODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_DEACTIVE_META_NODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_GET_ALL_META_NODE_INFO] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_SHIFT_LNN_GEAR] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_RIPPLE_STATS] = nullptr;
    memberPermissionMap_[SERVER_GET_SOFTBUS_SPEC_OBJECT] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_BUS_CENTER_EX_OBJ] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
}

int32_t SoftBusServerStub::OnRemoteRequest(uint32_t code,
    MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SoftbusRecordCalledApiCnt(code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        COMM_LOGE(COMM_SVC, "SOFTBUS_SERVER_NOT_INIT ReadInterfaceToken failed!");
        return SOFTBUS_ERR;
    }
    if (!GetServerIsInit()) {
        COMM_LOGE(COMM_SVC, "server not init");
        if (!reply.WriteInt32(SOFTBUS_SERVER_NOT_INIT)) {
            COMM_LOGE(COMM_SVC, "SOFTBUS_SERVER_NOT_INIT write reply failed!");
        }
        return SOFTBUS_ERR;
    }

    auto itPerm = memberPermissionMap_.find(code);
    if (itPerm != memberPermissionMap_.end()) {
        const char *permission = itPerm->second;
        if ((permission != nullptr) &&
            (CheckAndRecordAccessToken(permission) != PERMISSION_GRANTED)) {
            SoftbusReportPermissionFaultEvt(code);
            COMM_LOGE(COMM_SVC, "access token permission denied! permission=%{public}s", permission);
            pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
            TransAlarmExtra extra = {
                .conflictName = NULL,
                .conflictedName = NULL,
                .occupyedName = NULL,
                .sessionName = NULL,
                .callerPid = (int32_t)callingPid,
                .methodId = (int32_t)code,
                .permissionName = permission,
            };
            TRANS_ALARM(NO_PERMISSION_ALARM, CONTROL_ALARM_TYPE, extra);
            return SOFTBUS_ACCESS_TOKEN_DENIED;
        }
    }
    
    const auto &itFunc = memberFuncMap_.find(code);
    if (itFunc != memberFuncMap_.end()) {
        auto memberFunc = itFunc->second;
        if (memberFunc != nullptr) {
            return (this->*memberFunc)(data, reply);
        }
    }
    COMM_LOGI(COMM_SVC, "default case, need check.");
    return IPCObjectStub::OnRemoteRequest(code, data, reply, option);
}

int32_t SoftBusServerStub::StartDiscoveryInner(MessageParcel &data, MessageParcel &reply)
{
    SubscribeInfo subInfo;
    (void)memset_s(&subInfo, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "StartDiscoveryInner read pkgName failed!");
        return SOFTBUS_ERR;
    }

    uint32_t code = SERVER_START_DISCOVERY;
    SoftbusRecordCalledApiInfo(pkgName, code);
    subInfo.subscribeId = data.ReadInt32();
    subInfo.mode = (DiscoverMode)data.ReadInt32();
    subInfo.medium = (ExchangeMedium)data.ReadInt32();
    subInfo.freq = (ExchangeFreq)data.ReadInt32();
    subInfo.isSameAccount = data.ReadBool();
    subInfo.isWakeRemote = data.ReadBool();
    subInfo.capability = data.ReadCString();
    if (subInfo.capability == nullptr) {
        COMM_LOGE(COMM_SVC, "StartDiscoveryInner read capability failed!");
        return SOFTBUS_ERR;
    }
    subInfo.dataLen = data.ReadUint32();
    if (subInfo.dataLen > 0 && subInfo.dataLen < MAX_CAPABILITYDATA_LEN) {
        subInfo.capabilityData = const_cast<unsigned char *>(
            reinterpret_cast<const unsigned char *>(data.ReadCString()));
        if (subInfo.capabilityData == nullptr) {
            COMM_LOGE(COMM_SVC, "StartDiscoveryInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        subInfo.capabilityData = nullptr;
        subInfo.dataLen = 0;
    }
    int32_t retReply = StartDiscovery(pkgName, &subInfo);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StartDiscoveryInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopDiscoveryInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "StopDiscoveryInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t code = SERVER_STOP_DISCOVERY;
    SoftbusRecordCalledApiInfo(pkgName, code);
    int32_t subscribeId = data.ReadInt32();
    COMM_LOGI(COMM_SVC, "StopDiscoveryInner pkgName=%{public}s, subscribeId=%{public}d!\n", pkgName, subscribeId);
    int32_t retReply = StopDiscovery(pkgName, subscribeId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StopDiscoveryInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PublishServiceInner(MessageParcel &data, MessageParcel &reply)
{
    PublishInfo pubInfo;
    (void)memset_s(&pubInfo, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "PublishServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t code = SERVER_PUBLISH_SERVICE;
    SoftbusRecordCalledApiInfo(pkgName, code);
    pubInfo.publishId = data.ReadInt32();
    pubInfo.mode = (DiscoverMode)data.ReadInt32();
    pubInfo.medium = (ExchangeMedium)data.ReadInt32();
    pubInfo.freq = (ExchangeFreq)data.ReadInt32();
    pubInfo.capability = data.ReadCString();
    if (pubInfo.capability == nullptr) {
        COMM_LOGE(COMM_SVC, "PublishServiceInner read capability failed!");
        return SOFTBUS_ERR;
    }
    pubInfo.dataLen = data.ReadUint32();
    if (pubInfo.dataLen > 0 && pubInfo.dataLen < MAX_CAPABILITYDATA_LEN) {
        pubInfo.capabilityData = const_cast<unsigned char *>(
            reinterpret_cast<const unsigned char*>(data.ReadCString()));
        if (pubInfo.capabilityData == nullptr) {
            COMM_LOGE(COMM_SVC, "PublishServiceInner read capabilityData failed!");
            return SOFTBUS_ERR;
        }
    } else {
        pubInfo.capabilityData = nullptr;
        pubInfo.dataLen = 0;
    }
    int32_t retReply = PublishService(pkgName, &pubInfo);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "PublishServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::UnpublishServiceInner(MessageParcel &data, MessageParcel &reply)
{
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "UnpublishServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t code = SERVER_UNPUBLISH_SERVICE;
    SoftbusRecordCalledApiInfo(pkgName, code);
    int32_t publishId = data.ReadInt32();
    int32_t retReply = UnPublishService(pkgName, publishId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "UnpublishServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SoftbusRegisterServiceInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    auto remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner read systemAbilityId failed!");
        return SOFTBUS_ERR;
    }
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t code = MANAGE_REGISTER_SERVICE;
    SoftbusRecordCalledApiInfo(pkgName, code);
    int32_t retReply = SoftbusRegisterService(pkgName, remote);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}
#ifdef SUPPORT_BUNDLENAME
static bool IsObjectstoreDbSessionName(const char* sessionName)
{
#define OBJECTSTORE_DB_SESSION_NAME "objectstoreDB-*"
    regex_t regComp;
    if (regcomp(&regComp, OBJECTSTORE_DB_SESSION_NAME, REG_EXTENDED | REG_NOSUB) != 0) {
        COMM_LOGE(COMM_SVC, "regcomp failed.");
        return false;
    }
    bool compare = (regexec(&regComp, sessionName, 0, NULL, 0) == 0);
    regfree(&regComp);
    return compare;
}

static int32_t GetBundleName(pid_t callingUid, std::string &bundleName)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
            SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get system ability manager.");
        return SOFTBUS_ERR;
    }
    sptr<IRemoteObject> remoteObject =
            systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get bundle manager service.");
        return SOFTBUS_ERR;
    }
    sptr<AppExecFwk::IBundleMgr> iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        COMM_LOGE(COMM_SVC, "iface_cast failed");
        return SOFTBUS_ERR;
    }
    if (iBundleMgr->GetNameForUid(callingUid, bundleName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundleName failed");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t CheckSessionName(const char* sessionName, pid_t callingUid)
{
#define SESSION_NAME "objectstoreDB-"
    if (IsObjectstoreDbSessionName(sessionName)) {
        std::string bundleName;
        if (GetBundleName(callingUid, bundleName) != 0) {
            COMM_LOGE(COMM_SVC, "get bundle name failed");
            return SOFTBUS_ERR;
        }
        if (strcmp(bundleName.c_str(), sessionName + strlen(SESSION_NAME)) != 0) {
            COMM_LOGE(COMM_SVC, "bundle name is different from session name");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}
#endif

int32_t SoftBusServerStub::CreateSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "CreateSessionServerInner read pkgName failed!");
        return SOFTBUS_ERR;
    }

    const char *sessionName = data.ReadCString();
    uint32_t code = SERVER_CREATE_SESSION_SERVER;
    SoftbusRecordCalledApiInfo(pkgName, code);
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }
    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }

#ifdef SUPPORT_BUNDLENAME
    if (CheckSessionName(sessionName, callingUid) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
#endif

    retReply = CreateSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "CreateSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemoveSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner read pkgName failed!");
        return SOFTBUS_ERR;
    }

    const char *sessionName = data.ReadCString();
    uint32_t code = SERVER_REMOVE_SESSION_SERVER;
    SoftbusRecordCalledApiInfo(pkgName, code);
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }

    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner check perm failed");
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }

    retReply = RemoveSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static void ReadSessionAttrs(MessageParcel &data, SessionAttribute *getAttr)
{
    if (getAttr == nullptr) {
        COMM_LOGE(COMM_SVC, "ReadSessionAttrs getAttr is nullptr");
        return;
    }
    LinkType *pGetArr = nullptr;

    getAttr->dataType = data.ReadInt32();
    getAttr->linkTypeNum = data.ReadInt32();

    if (getAttr->linkTypeNum > 0) {
        pGetArr = const_cast<LinkType *>(reinterpret_cast<const LinkType *>(
            data.ReadBuffer(sizeof(LinkType) * getAttr->linkTypeNum)));
    }

    if (pGetArr != nullptr && getAttr->linkTypeNum <= LINK_TYPE_MAX) {
        (void)memcpy_s(getAttr->linkType, sizeof(LinkType) * LINK_TYPE_MAX,
                       pGetArr, sizeof(LinkType) * getAttr->linkTypeNum);
    }

    getAttr->attr.streamAttr.streamType = data.ReadInt32();
    getAttr->fastTransDataSize = data.ReadUint16();
    if (getAttr->fastTransDataSize != 0) {
        getAttr->fastTransData = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(
            data.ReadRawData(getAttr->fastTransDataSize)));
    }
}

static bool ReadQosInfo(MessageParcel& data, SessionParam &param)
{
    if (!data.ReadBool(param.isQosLane)) {
        COMM_LOGE(COMM_SVC, "failed to read isQosLane");
        return false;
    }
    if (!param.isQosLane) {
        return true;
    }

    if (!data.ReadUint32(param.qosCount)) {
        COMM_LOGE(COMM_SVC, "failed to read qosCount");
        return false;
    }
    if (param.qosCount == 0) {
        return true;
    }

    if (param.qosCount > QOS_TYPE_BUTT) {
        COMM_LOGE(COMM_SVC, "read invalid qosCount=%{public}" PRIu32, param.qosCount);
        return false;
    }

    const QosTV *qosInfo = (QosTV *)data.ReadBuffer(sizeof(QosTV) * param.qosCount);
    if (qosInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "failed to read qos data");
        return false;
    }

    if (memcpy_s(param.qos, sizeof(QosTV) * QOS_TYPE_BUTT, qosInfo, sizeof(QosTV) * param.qosCount) != EOK) {
        COMM_LOGE(COMM_SVC, "failed memcpy qos info");
        return false;
    }
    return true;
}

static void ReadSessionInfo(MessageParcel& data, SessionParam &param)
{
    param.sessionName = data.ReadCString();
    param.peerSessionName = data.ReadCString();
    param.peerDeviceId = data.ReadCString();
    param.groupId = data.ReadCString();
}

int32_t SoftBusServerStub::OpenSessionInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t retReply;
    SessionParam param;
    SessionAttribute getAttr;
    (void)memset_s(&param, sizeof(SessionParam), 0, sizeof(SessionParam));
    (void)memset_s(&getAttr, sizeof(SessionAttribute), 0, sizeof(SessionAttribute));

    TransSerializer transSerializer;
    int64_t timeStart = 0;
    int64_t timediff = 0;
    SoftBusOpenSessionStatus isSucc = SOFTBUS_EVT_OPEN_SESSION_FAIL;
    ReadSessionInfo(data, param);
    ReadSessionAttrs(data, &getAttr);
    param.attr = &getAttr;
    if (!ReadQosInfo(data, param)) {
        COMM_LOGE(COMM_SVC, "failed to read qos info");
        return SOFTBUS_ERR;
    }

    if (param.sessionName == nullptr || param.peerSessionName == nullptr || param.peerDeviceId == nullptr ||
        param.groupId == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }
    if (TransCheckAccessControl(param.peerDeviceId) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
    if (CheckOpenSessionPermission(&param) != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_PERMISSION_DENIED);
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
#ifdef SUPPORT_BUNDLENAME
    pid_t callingUid;
    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    if (CheckSessionName(param.sessionName, callingUid) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
#endif

    timeStart = GetSoftbusRecordTimeMillis();
    retReply = OpenSession(&param, &(transSerializer.transInfo));
    timediff = GetSoftbusRecordTimeMillis() - timeStart;

    isSucc = (retReply == SOFTBUS_OK) ? SOFTBUS_EVT_OPEN_SESSION_SUCC : SOFTBUS_EVT_OPEN_SESSION_FAIL;
    SoftbusRecordOpenSession(isSucc, static_cast<uint32_t>(timediff));

EXIT:
    transSerializer.ret = retReply;
    if (!reply.WriteRawData(&transSerializer, sizeof(TransSerializer))) {
        COMM_LOGE(COMM_SVC, "OpenSessionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenAuthSessionInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t retReply;
    const char *sessionName = data.ReadCString();
    ConnectionAddr *addrInfo = const_cast<ConnectionAddr *>(
        reinterpret_cast<const ConnectionAddr *>(data.ReadRawData(sizeof(ConnectionAddr))));
    if (sessionName == nullptr || addrInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "OpenAuthSessionInner get param failed!");
        return SOFTBUS_ERR;
    }
    SessionParam param;
    param.sessionName = sessionName;
    param.peerSessionName = sessionName;
    retReply = CheckOpenSessionPermission(&param);
    if (retReply != SOFTBUS_OK) {
        goto EXIT;
    }
    retReply = OpenAuthSession(sessionName, addrInfo);
    COMM_LOGI(COMM_SVC, "OpenAuthSession retReply=%{public}d", retReply);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "OpenSessionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::NotifyAuthSuccessInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t channelId;
    int32_t channelType;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner read channel type failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = NotifyAuthSuccess(channelId, channelType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CloseChannelInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner read channel channel type failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = CloseChannel(channelId, channelType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SendMessageInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "SendMessage read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "SendMessage read channel type failed!");
        return SOFTBUS_ERR;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SVC, "SendMessage dataInfo len failed!");
        return SOFTBUS_ERR;
    }
    void *dataInfo = const_cast<void *>(reinterpret_cast<const void *>(
        data.ReadRawData(len)));
    if (dataInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "SendMessage read dataInfo failed!");
        return SOFTBUS_ERR;
    }
    int32_t msgType;
    if (!data.ReadInt32(msgType)) {
        COMM_LOGE(COMM_SVC, "SendMessage message type failed!");
        return SOFTBUS_ERR;
    }
    if (CheckChannelPermission(channelId, channelType) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "SendMessage permission check failed!");
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t retReply = SendMessage(channelId, channelType, dataInfo, len, msgType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SendMessage write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::EvaluateQosInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *peerNetworkId = data.ReadCString();
    if (peerNetworkId == nullptr) {
        COMM_LOGE(COMM_SVC, "EvaluateQos read peerNetworkId failed!");
        return SOFTBUS_IPC_ERR;
    }

    int32_t dataTypeNumber;
    if (!data.ReadInt32(dataTypeNumber)) {
        COMM_LOGE(COMM_SVC, "EvaluateQos read dataType failed!");
        return SOFTBUS_IPC_ERR;
    }

    TransDataType dataType = static_cast<TransDataType>(dataTypeNumber);
    if (dataType < DATA_TYPE_MESSAGE || dataType >= DATA_TYPE_BUTT) {
        COMM_LOGE(COMM_SVC, "EvaluateQos read dataType failed!");
        return SOFTBUS_IPC_ERR;
    }

    uint32_t qosCount;
    if (!data.ReadUint32(qosCount)) {
        COMM_LOGE(COMM_SVC, "EvaluateQos read qosCount failed!");
        return SOFTBUS_IPC_ERR;
    }

    if (qosCount > QOS_TYPE_BUTT) {
        COMM_LOGE(COMM_SVC, "EvaluateQos invalid qosCount=%{public}" PRIu32, qosCount);
        return SOFTBUS_IPC_ERR;
    }

    const QosTV *qos = nullptr;
    if (qosCount > 0) {
        qos = (QosTV *)data.ReadBuffer(sizeof(QosTV) * qosCount);
        if (qos == nullptr) {
            COMM_LOGE(COMM_SVC, "EvaluateQos failed to read qos data");
            return SOFTBUS_IPC_ERR;
        }
    }

    int32_t retReply = EvaluateQos(peerNetworkId, dataType, qos, qosCount);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "EvaluateQos write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::JoinLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t addrTypeLen;
    if (!data.ReadUint32(addrTypeLen) || addrTypeLen != sizeof(ConnectionAddr)) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner read addr type failed! length=%{public}d", addrTypeLen);
        return SOFTBUS_IPC_ERR;
    }
    void *addr = const_cast<void *>(reinterpret_cast<const void *>(
        data.ReadRawData(addrTypeLen)));
    if (addr == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner read addr failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = JoinLNN(clientName, addr, addrTypeLen);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::LeaveLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusLeaveLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusLeaveLNNInner read networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = LeaveLNN(clientName, networkId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetAllOnlineNodeInfoInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    void *nodeInfo = nullptr;
    int32_t infoNum;
    uint32_t infoTypeLen;

    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.ReadUint32(infoTypeLen)) {
        COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner read info type length failed");
        return SOFTBUS_IPC_ERR;
    }
    if (GetAllOnlineNodeInfo(clientName, &nodeInfo, infoTypeLen, &infoNum) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner get info failed");
        return SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR;
    }
    if (infoNum < 0 || (infoNum > 0 && nodeInfo == nullptr)) {
        COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner node info is invalid");
        return SOFTBUS_IPC_ERR;
    }
    if (!reply.WriteInt32(infoNum)) {
        COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner write infoNum failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_ERR;
    }
    int32_t ret = SOFTBUS_OK;
    if (infoNum > 0) {
        if (!reply.WriteRawData(nodeInfo, static_cast<int32_t>(infoTypeLen * infoNum))) {
            COMM_LOGE(COMM_SVC, "GetAllOnlineNodeInfoInner write node info failed!");
            ret = SOFTBUS_IPC_ERR;
        }
        SoftBusFree(nodeInfo);
    }
    return ret;
}

int32_t SoftBusServerStub::GetLocalDeviceInfoInner(MessageParcel &data, MessageParcel &reply)
{
    void *nodeInfo = nullptr;
    uint32_t infoTypeLen;

    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "GetLocalDeviceInfoInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }

    infoTypeLen = sizeof(NodeBasicInfo);
    nodeInfo = SoftBusCalloc(infoTypeLen);
    if (nodeInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "GetLocalDeviceInfoInner malloc info type length failed");
        return SOFTBUS_IPC_ERR;
    }
    if (GetLocalDeviceInfo(clientName, nodeInfo, infoTypeLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "GetLocalDeviceInfoInner get local info failed");
        SoftBusFree(nodeInfo);
        return SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR;
    }
    if (!reply.WriteRawData(nodeInfo, infoTypeLen)) {
        COMM_LOGE(COMM_SVC, "GetLocalDeviceInfoInner write node info failed!");
        SoftBusFree(nodeInfo);
        return SOFTBUS_IPC_ERR;
    }
    SoftBusFree(nodeInfo);
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetNodeKeyInfoLen(int32_t key)
{
    return LnnGetNodeKeyInfoLen(key);
}

static void PrintNetworkId(const char *networkId)
{
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    COMM_LOGI(COMM_SVC, "networkId=%{public}s", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);
}

int32_t SoftBusServerStub::GetNodeKeyInfoInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    const char *networkId = data.ReadCString();
    if (clientName == nullptr || networkId == nullptr) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner read clientName or networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    PrintNetworkId(networkId);
    int32_t key;
    if (!data.ReadInt32(key)) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner read key failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t infoLen = GetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner info len failed!");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t len;
    if (!data.ReadInt32(len)) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner read len failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (len < infoLen) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner read len is invalid param, len=%{public}d, infoLen=%{public}d", len,
            infoLen);
        return SOFTBUS_INVALID_PARAM;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == nullptr) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner malloc buffer failed!");
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetNodeKeyInfo(clientName, networkId, key, static_cast<unsigned char *>(buf), infoLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner get key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_NETWORK_NODE_KEY_INFO_ERR;
    }
    if (!reply.WriteInt32(infoLen)) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner write info length failed!");
        SoftBusFree(buf);
        return SOFTBUS_IPC_ERR;
    }
    if (!reply.WriteRawData(buf, infoLen)) {
        COMM_LOGE(COMM_SVC, "GetNodeKeyInfoInner write key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_IPC_ERR;
    }
    SoftBusFree(buf);
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SetNodeDataChangeFlagInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SetNodeDataChangeFlag read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    const char *networkId = data.ReadCString();
    if (networkId == nullptr) {
        COMM_LOGE(COMM_SVC, "SetNodeDataChangeFlag read networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int16_t changeFlag;
    if (!data.ReadInt16(changeFlag)) {
        COMM_LOGE(COMM_SVC, "SetNodeDataChangeFlag read key failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = SetNodeDataChangeFlag(clientName, networkId, changeFlag);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SetNodeDataChangeFlag write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StartTimeSyncInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "StartTimeSyncInner read pkgName failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t code = SERVER_START_TIME_SYNC;
    SoftbusRecordCalledApiInfo(pkgName, code);
    const char *targetNetworkId = data.ReadCString();
    if (targetNetworkId == nullptr) {
        COMM_LOGE(COMM_SVC, "StartTimeSyncInner read targetNetworkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t accuracy;
    if (!data.ReadInt32(accuracy)) {
        COMM_LOGE(COMM_SVC, "StartTimeSyncInner read accuracy failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t period;
    if (!data.ReadInt32(period)) {
        COMM_LOGE(COMM_SVC, "StartTimeSyncInner read period failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = StartTimeSync(pkgName, targetNetworkId, accuracy, period);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StartTimeSyncInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopTimeSyncInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "StopTimeSyncInner read pkgName failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint32_t code = SERVER_STOP_TIME_SYNC;
    SoftbusRecordCalledApiInfo(pkgName, code);
    const char *targetNetworkId = data.ReadCString();
    if (targetNetworkId == nullptr) {
        COMM_LOGE(COMM_SVC, "StopTimeSyncInner read targetNetworkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = StopTimeSync(pkgName, targetNetworkId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StopTimeSyncInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::QosReportInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel Id failed!");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel channel type failed!");
        return SOFTBUS_ERR;
    }
    int32_t appType;
    if (!data.ReadInt32(appType)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel appType failed!");
        return SOFTBUS_ERR;
    }
    int32_t quality;
    if (!data.ReadInt32(quality)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read quality failed!");
        return SOFTBUS_ERR;
    }

    int32_t retReply = QosReport(channelId, channelType, appType, quality);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "QosReportInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StreamStatsInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner read channelId fail");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner read channelType fail");
        return SOFTBUS_ERR;
    }
    StreamSendStats *stats = const_cast<StreamSendStats *>(reinterpret_cast<const StreamSendStats *>(
        data.ReadRawData(sizeof(StreamSendStats))));
    if (stats == nullptr) {
        COMM_LOGE(COMM_SVC, "read StreamSendStats fail, stats is nullptr");
        return SOFTBUS_ERR;
    }
    int32_t retReply = StreamStats(channelId, channelType, stats);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner write reply fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RippleStatsInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner read channelId fail");
        return SOFTBUS_ERR;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner read channelType fail");
        return SOFTBUS_ERR;
    }
    TrafficStats *stats = const_cast<TrafficStats *>(reinterpret_cast<const TrafficStats *>(
        data.ReadRawData(sizeof(TrafficStats))));
    if (stats == nullptr) {
        COMM_LOGE(COMM_SVC, "read rippleStats fail, stats is nullptr");
        return SOFTBUS_ERR;
    }
    int32_t retReply = RippleStats(channelId, channelType, stats);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner write reply fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GrantPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t uid = 0;
    int32_t pid = 0;
    const char *sessionName = nullptr;
    int32_t ret = CheckDynamicPermission();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "GrantPermissionInner check permission failed. ret=%{public}d!", ret);
        goto EXIT;
    }

    uid = data.ReadInt32();
    pid = data.ReadInt32();
    sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        COMM_LOGE(COMM_SVC, "GrantPermissionInner read sessionName failed!");
        goto EXIT;
    }
    ret = GrantTransPermission(uid, pid, sessionName);
EXIT:
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "GrantPermissionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemovePermissionInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = nullptr;
    int32_t ret = CheckDynamicPermission();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "RemovePermissionInner check permission failed. ret=%{public}d!", ret);
        goto EXIT;
    }

    sessionName = data.ReadCString();
    if (sessionName == nullptr) {
        COMM_LOGE(COMM_SVC, "RemovePermissionInner read sessionName failed!");
        goto EXIT;
    }
    ret = RemoveTransPermission(sessionName);
EXIT:
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "RemovePermissionInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    PublishInfo info;
    int32_t mode;
    int32_t medium;
    int32_t freq;
    (void)memset_s(&info, sizeof(PublishInfo), 0, sizeof(PublishInfo));
    if (!data.ReadInt32(info.publishId) || !data.ReadInt32(mode) || !data.ReadInt32(medium) ||
        !data.ReadInt32(freq)) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read common publish info failed!");
        return SOFTBUS_IPC_ERR;
    }
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchangeMedium)medium;
    info.freq = (ExchangeFreq)freq;
    info.capability = data.ReadCString();
    if (info.capability == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read capability failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.ReadUint32(info.dataLen)) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read dataLen failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = const_cast<unsigned char *>(
            reinterpret_cast<const unsigned char*>(data.ReadCString()));
        if (info.capabilityData == nullptr) {
            COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read capabilityData failed!");
            return SOFTBUS_IPC_ERR;
        }
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }
    if (!data.ReadBool(info.ranging)) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner read ranging failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = PublishLNN(clientName, &info);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusPublishLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopPublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusStopPublishLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t publishId;
    if (!data.ReadInt32(publishId)) {
        COMM_LOGE(COMM_SVC, "SoftbusStopPublishLNNInner read publishId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = StopPublishLNN(clientName, publishId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusStopPublishLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    SubscribeInfo info;
    int32_t mode;
    int32_t medium;
    int32_t freq;
    (void)memset_s(&info, sizeof(SubscribeInfo), 0, sizeof(SubscribeInfo));
    if (!data.ReadInt32(info.subscribeId) || !data.ReadInt32(mode) || !data.ReadInt32(medium) ||
        !data.ReadInt32(freq)) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read common subscribe info failed!");
        return SOFTBUS_IPC_ERR;
    }
    info.mode = (DiscoverMode)mode;
    info.medium = (ExchangeMedium)medium;
    info.freq = (ExchangeFreq)freq;
    if (!data.ReadBool(info.isSameAccount) || !data.ReadBool(info.isWakeRemote)) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read subscribe info flag failed!");
        return SOFTBUS_IPC_ERR;
    }
    info.capability = data.ReadCString();
    if (info.capability == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read capability failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!data.ReadUint32(info.dataLen)) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read dataLen failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        info.capabilityData = const_cast<unsigned char *>(
            reinterpret_cast<const unsigned char*>(data.ReadCString()));
        if (info.capabilityData == nullptr) {
            COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner read capabilityData failed!");
            return SOFTBUS_IPC_ERR;
        }
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }
    int32_t retReply = RefreshLNN(clientName, &info);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusRefreshLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopRefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    if (clientName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusStopRefreshLNNInner read clientName failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t refreshId;
    if (!data.ReadInt32(refreshId)) {
        COMM_LOGE(COMM_SVC, "SoftbusStopRefreshLNNInner read refreshId failed!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = StopRefreshLNN(clientName, refreshId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusStopRefreshLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ActiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    MetaNodeConfigInfo *info = const_cast<MetaNodeConfigInfo *>(
        reinterpret_cast<const MetaNodeConfigInfo *>(data.ReadRawData(sizeof(MetaNodeConfigInfo))));
    if (info == nullptr) {
        COMM_LOGE(COMM_SVC, "ActiveMetaNode read meta node config info failed!");
        return SOFTBUS_IPC_ERR;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = {0};
    if (ActiveMetaNode(info, metaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_ACTIVE_META_NODE_ERR;
    }
    if (!reply.WriteCString(metaNodeId)) {
        COMM_LOGE(COMM_SVC, "ActiveMetaNode write meta node id failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::DeactiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *metaNodeId = reinterpret_cast<const char *>(data.ReadCString());
    if (metaNodeId == nullptr) {
        COMM_LOGE(COMM_SVC, "DeactiveMetaNode read meta node id failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (DeactiveMetaNode(metaNodeId) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_DEACTIVE_META_NODE_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetAllMetaNodeInfoInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    int32_t infoNum;
    MetaNodeInfo infos[MAX_META_NODE_NUM];

    if (!data.ReadInt32(infoNum)) {
        COMM_LOGE(COMM_SVC, "GetAllMetaNodeInfo read infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (GetAllMetaNodeInfo(infos, &infoNum) != SOFTBUS_OK) {
        return SOFTBUS_NETWORK_GET_META_NODE_INFO_ERR;
    }
    if (!reply.WriteInt32(infoNum)) {
        COMM_LOGE(COMM_SVC, "GetAllMetaNodeInfo write infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (infoNum > 0 && !reply.WriteRawData(infos, infoNum * sizeof(MetaNodeInfo))) {
        COMM_LOGE(COMM_SVC, "GetAllMetaNodeInfo write meta node info failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ShiftLNNGearInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGI(COMM_SVC, "enter");
    const char *targetNetworkId = nullptr;
    const GearMode *mode = nullptr;

    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strnlen(pkgName, PKG_NAME_SIZE_MAX) >= PKG_NAME_SIZE_MAX) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read pkgName failed!");
        return SOFTBUS_ERR;
    }
    uint32_t code = SERVER_SHIFT_LNN_GEAR;
    SoftbusRecordCalledApiInfo(pkgName, code);
    const char *callerId = data.ReadCString();
    if (callerId == nullptr || strnlen(callerId, CALLER_ID_MAX_LEN) >= CALLER_ID_MAX_LEN) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read callerId failed!");
        return SOFTBUS_ERR;
    }
    if (!data.ReadBool()) {
        targetNetworkId = data.ReadCString();
        if (targetNetworkId == nullptr || strnlen(targetNetworkId, NETWORK_ID_BUF_LEN) != NETWORK_ID_BUF_LEN - 1) {
            COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read targetNetworkId failed!");
            return SOFTBUS_ERR;
        }
    }
    mode = reinterpret_cast<const GearMode *>(data.ReadRawData(sizeof(GearMode)));
    if (mode == nullptr) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read mode failed!");
        return SOFTBUS_ERR;
    }
    int32_t retReply = ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner write reply failed!");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetSoftbusSpecObjectInner(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object;
    int32_t ret = GetSoftbusSpecObject(object);
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "GetSoftbusSpecObjectInner write reply failed!");
        return SOFTBUS_ERR;
    }
    if (ret == SOFTBUS_OK) {
        if (!reply.WriteRemoteObject(object)) {
            COMM_LOGE(COMM_SVC, "GetSoftbusSpecObjectInner write object failed!");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetBusCenterExObjInner(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object;
    int32_t ret = GetBusCenterExObj(object);
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "GetBusCenterExObjInner write reply failed!");
        return SOFTBUS_ERR;
    }
    if (ret == SOFTBUS_OK) {
        if (!reply.WriteRemoteObject(object)) {
            COMM_LOGE(COMM_SVC, "GetBusCenterExObjInner write object failed!");
            return SOFTBUS_ERR;
        }
    }
    return SOFTBUS_OK;
}
} // namespace OHOS
