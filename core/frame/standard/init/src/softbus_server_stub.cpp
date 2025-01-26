/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "regex.h"
#include "securec.h"

#include "access_control.h"
#include "anonymizer.h"
#include "ipc_skeleton.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_permission.h"
#include "softbus_server_frame.h"
#include "softbus_server_ipc_interface_code.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_log.h"
#include "trans_network_statistics.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_sessionconn.h"

#ifdef SUPPORT_BUNDLENAME
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "ohos_account_kits.h"
#include "os_account_manager.h"
#include "system_ability_definition.h"
#endif

#define READ_PARCEL_WITH_RET(parcel, type, data, retVal)        \
    do {                                                        \
        if (!(parcel).Read##type(data)) {                       \
            COMM_LOGE(COMM_SVC, "read data failed.");           \
            return (retVal);                                    \
        }                                                       \
    } while (false)                                             \

namespace OHOS {
    namespace {
        constexpr int32_t MSG_MAX_SIZE = 1024 * 2;
        constexpr int32_t DMS_CALLING_UID = 5522;
        static const char *DB_PACKAGE_NAME = "distributeddata-default";
        static const char *DM_PACKAGE_NAME = "ohos.distributedhardware.devicemanager";
    }


int32_t SoftBusServerStub::CheckOpenSessionPermission(const SessionParam *param)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
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

    if (!CheckUidAndPid(param->sessionName, callingUid, callingPid)) {
        char *tmpName = NULL;
        Anonymize(param->sessionName, &tmpName);
        COMM_LOGE(COMM_SVC, "Check Uid and Pid failed, sessionName=%{public}s", AnonymizeWrapper(tmpName));
        AnonymizeFree(tmpName);
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }

    if (CheckTransSecLevel(param->sessionName, param->peerSessionName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "OpenSession sec level invalid");
        return SOFTBUS_PERMISSION_DENIED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CheckChannelPermission(int32_t channelId, int32_t channelType)
{
    char pkgName[PKG_NAME_SIZE_MAX] = { 0 };
    char sessionName[SESSION_NAME_SIZE_MAX] = { 0 };
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

static void SoftbusReportPermissionFaultEvt(uint32_t ipcCode)
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
    memberFuncMap_[MANAGE_REGISTER_SERVICE] = &SoftBusServerStub::SoftbusRegisterServiceInner;
    memberFuncMap_[SERVER_CREATE_SESSION_SERVER] = &SoftBusServerStub::CreateSessionServerInner;
    memberFuncMap_[SERVER_REMOVE_SESSION_SERVER] = &SoftBusServerStub::RemoveSessionServerInner;
    memberFuncMap_[SERVER_RELEASE_RESOURCES] = &SoftBusServerStub::ReleaseResourcesInner;
    memberFuncMap_[SERVER_OPEN_SESSION] = &SoftBusServerStub::OpenSessionInner;
    memberFuncMap_[SERVER_OPEN_AUTH_SESSION] = &SoftBusServerStub::OpenAuthSessionInner;
    memberFuncMap_[SERVER_NOTIFY_AUTH_SUCCESS] = &SoftBusServerStub::NotifyAuthSuccessInner;
    memberFuncMap_[SERVER_CLOSE_CHANNEL] = &SoftBusServerStub::CloseChannelInner;
    memberFuncMap_[SERVER_CLOSE_CHANNEL_STATISTICS] = &SoftBusServerStub::CloseChannelWithStatisticsInner;
    memberFuncMap_[SERVER_SESSION_SENDMSG] = &SoftBusServerStub::SendMessageInner;
    memberFuncMap_[SERVER_EVALUATE_QOS] = &SoftBusServerStub::EvaluateQosInner;
    memberFuncMap_[SERVER_JOIN_LNN] = &SoftBusServerStub::JoinLNNInner;
    memberFuncMap_[SERVER_LEAVE_LNN] = &SoftBusServerStub::LeaveLNNInner;
    memberFuncMap_[SERVER_GET_ALL_ONLINE_NODE_INFO] = &SoftBusServerStub::GetAllOnlineNodeInfoInner;
    memberFuncMap_[SERVER_GET_LOCAL_DEVICE_INFO] = &SoftBusServerStub::GetLocalDeviceInfoInner;
    memberFuncMap_[SERVER_GET_NODE_KEY_INFO] = &SoftBusServerStub::GetNodeKeyInfoInner;
    memberFuncMap_[SERVER_SET_NODE_DATA_CHANGE_FLAG] = &SoftBusServerStub::SetNodeDataChangeFlagInner;
    memberFuncMap_[SERVER_REG_DATA_LEVEL_CHANGE_CB] = &SoftBusServerStub::RegDataLevelChangeCbInner;
    memberFuncMap_[SERVER_UNREG_DATA_LEVEL_CHANGE_CB] = &SoftBusServerStub::UnregDataLevelChangeCbInner;
    memberFuncMap_[SERVER_SET_DATA_LEVEL] = &SoftBusServerStub::SetDataLevelInner;
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
    memberFuncMap_[SERVER_SYNC_TRUSTED_RELATION] = &SoftBusServerStub::SyncTrustedRelationShipInner;
    memberFuncMap_[SERVER_RIPPLE_STATS] = &SoftBusServerStub::RippleStatsInner;
    memberFuncMap_[SERVER_GET_SOFTBUS_SPEC_OBJECT] = &SoftBusServerStub::GetSoftbusSpecObjectInner;
    memberFuncMap_[SERVER_GET_BUS_CENTER_EX_OBJ] = &SoftBusServerStub::GetBusCenterExObjInner;
    memberFuncMap_[SERVER_PROCESS_INNER_EVENT] = &SoftBusServerStub::ProcessInnerEventInner;
    memberFuncMap_[SERVER_PRIVILEGE_CLOSE_CHANNEL] = &SoftBusServerStub::PrivilegeCloseChannelInner;
    memberFuncMap_[SERVER_SET_DISPLAY_NAME] = &SoftBusServerStub::SetDisplayNameInner;
}

void SoftBusServerStub::InitMemberPermissionMap()
{
    memberPermissionMap_[MANAGE_REGISTER_SERVICE] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_CREATE_SESSION_SERVER] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_REMOVE_SESSION_SERVER] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_RELEASE_RESOURCES] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_OPEN_SESSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_OPEN_AUTH_SESSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_NOTIFY_AUTH_SUCCESS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_CLOSE_CHANNEL] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_CLOSE_CHANNEL_STATISTICS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_SESSION_SENDMSG] = nullptr;
    memberPermissionMap_[SERVER_JOIN_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_JOIN_METANODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_LEAVE_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_LEAVE_METANODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_GET_ALL_ONLINE_NODE_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_LOCAL_DEVICE_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_NODE_KEY_INFO] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_SET_NODE_DATA_CHANGE_FLAG] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_REG_DATA_LEVEL_CHANGE_CB] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_UNREG_DATA_LEVEL_CHANGE_CB] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_SET_DATA_LEVEL] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_START_TIME_SYNC] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_TIME_SYNC] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_QOS_REPORT] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_STREAM_STATS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GRANT_PERMISSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_REMOVE_PERMISSION] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_PUBLISH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_PUBLISH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_REFRESH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_STOP_REFRESH_LNN] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_ACTIVE_META_NODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_DEACTIVE_META_NODE] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_GET_ALL_META_NODE_INFO] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_SHIFT_LNN_GEAR] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_SYNC_TRUSTED_RELATION] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_RIPPLE_STATS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_SOFTBUS_SPEC_OBJECT] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_GET_BUS_CENTER_EX_OBJ] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
    memberPermissionMap_[SERVER_EVALUATE_QOS] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_PROCESS_INNER_EVENT] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_PRIVILEGE_CLOSE_CHANNEL] = OHOS_PERMISSION_DISTRIBUTED_DATASYNC;
    memberPermissionMap_[SERVER_SET_DISPLAY_NAME] = OHOS_PERMISSION_DISTRIBUTED_SOFTBUS_CENTER;
}

int32_t SoftBusServerStub::OnRemoteRequest(
    uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option)
{
    SoftbusRecordCalledApiCnt(code);
    if (data.ReadInterfaceToken() != GetDescriptor()) {
        COMM_LOGE(COMM_SVC, "SOFTBUS_SERVER_NOT_INIT ReadInterfaceToken failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (!GetServerIsInit()) {
        COMM_LOGE(COMM_SVC, "server not init");
        if (!reply.WriteInt32(SOFTBUS_SERVER_NOT_INIT)) {
            COMM_LOGE(COMM_SVC, "SOFTBUS_SERVER_NOT_INIT write reply failed!");
        }
        return SOFTBUS_IPC_ERR;
    }

    auto itPerm = memberPermissionMap_.find(code);
    if (itPerm != memberPermissionMap_.end()) {
        const char *permission = itPerm->second;
        uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
        if ((permission != nullptr) &&
            (!SoftBusCheckIsAccessAndRecordAccessToken(callingTokenId, permission))) {
            SoftbusReportPermissionFaultEvt(code);
            COMM_LOGE(COMM_SVC, "access token permission denied! permission=%{public}s, tokenId=%{public}d",
                permission, callingTokenId);
            pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
            TransAlarmExtra extra = {
                .callerPid = (int32_t)callingPid,
                .methodId = (int32_t)code,
                .conflictName = NULL,
                .conflictedName = NULL,
                .occupyedName = NULL,
                .permissionName = permission,
                .sessionName = NULL,
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

int32_t SoftBusServerStub::SoftbusRegisterServiceInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    auto remote = data.ReadRemoteObject();
    if (remote == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner read systemAbilityId failed!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    uint32_t code = MANAGE_REGISTER_SERVICE;
    SoftbusRecordCalledApiInfo(pkgName, code);
    int32_t retReply = SoftbusRegisterService(pkgName, remote);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusRegisterServiceInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

#ifdef SUPPORT_BUNDLENAME
static int32_t GetBundleName(pid_t callingUid, std::string &bundleName)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get system ability manager.");
        return SOFTBUS_TRANS_SYSTEM_ABILITY_MANAGER_FAILED;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get bundle manager service.");
        return SOFTBUS_TRANS_GET_SYSTEM_ABILITY_FAILED;
    }
    sptr<AppExecFwk::IBundleMgr> iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        COMM_LOGE(COMM_SVC, "iface_cast failed");
        return SOFTBUS_TRANS_GET_BUNDLE_MGR_FAILED;
    }
    if (iBundleMgr->GetNameForUid(callingUid, bundleName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundleName failed");
        return SOFTBUS_TRANS_GET_BUNDLENAME_FAILED;
    }
    return SOFTBUS_OK;
}

static int32_t GetAppId(const std::string &bundleName, std::string &appId)
{
    sptr<ISystemAbilityManager> systemAbilityManager =
        SystemAbilityManagerClient::GetInstance().GetSystemAbilityManager();
    if (systemAbilityManager == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get system ability manager.");
        return SOFTBUS_TRANS_SYSTEM_ABILITY_MANAGER_FAILED;
    }
    sptr<IRemoteObject> remoteObject = systemAbilityManager->GetSystemAbility(BUNDLE_MGR_SERVICE_SYS_ABILITY_ID);
    if (remoteObject == nullptr) {
        COMM_LOGE(COMM_SVC, "Failed to get bundle manager service.");
        return SOFTBUS_TRANS_GET_SYSTEM_ABILITY_FAILED;
    }
    sptr<AppExecFwk::IBundleMgr> iBundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (iBundleMgr == nullptr) {
        COMM_LOGE(COMM_SVC, "iface_cast failed");
        return SOFTBUS_TRANS_GET_BUNDLE_MGR_FAILED;
    }
    int32_t userId;
    auto result = AccountSA::OsAccountManager::GetForegroundOsAccountLocalId(userId);
    if (result != 0) {
        COMM_LOGE(COMM_SVC, "GetForegroundOsAccountLocalId failed result=%{public}d", result);
        return result;
    }
    AppExecFwk::BundleInfo bundleInfo;
    result = iBundleMgr->GetBundleInfoV9(bundleName,
        static_cast<int32_t>(AppExecFwk::GetBundleInfoFlag::GET_BUNDLE_INFO_WITH_SIGNATURE_INFO),
        bundleInfo, userId);
    if (result != 0) {
        COMM_LOGE(COMM_SVC, "GetBundleInfoV9 failed result=%{public}d", result);
        return result;
    }
    appId = bundleInfo.appId;
    return SOFTBUS_OK;
}

static int32_t CheckNormalAppSessionName(
    const char *sessionName, pid_t callingUid, std::string &strName)
{
    uint64_t callingFullTokenId = IPCSkeleton::GetCallingFullTokenID();
    if (SoftBusCheckIsNormalApp(callingFullTokenId, sessionName)) {
        std::string bundleName;
        int32_t result = GetBundleName(callingUid, bundleName);
        if (result != SOFTBUS_OK) {
            COMM_LOGE(COMM_SVC, "get bundle name failed");
            return result;
        }
        std::string appId;
        result = GetAppId(bundleName, appId);
        if (result != SOFTBUS_OK) {
            COMM_LOGE(COMM_SVC, "get appId failed");
            return result;
        }
        auto posName = strName.find("-");
        if (posName == std::string::npos) {
            COMM_LOGE(COMM_SVC, "not find bundleName");
            return SOFTBUS_TRANS_NOT_FIND_BUNDLENAME;
        }
        auto posId = strName.find("-", posName + 1);
        if (posId == std::string::npos) {
            COMM_LOGE(COMM_SVC, "not find appId");
            return SOFTBUS_TRANS_NOT_FIND_APPID;
        }
        if (strcmp(bundleName.c_str(), strName.substr(posName + 1, posId - posName - 1).c_str()) != 0) {
            COMM_LOGE(COMM_SVC, "bundleName is different from session name");
            return SOFTBUS_STRCMP_ERR;
        }
        if (strcmp(appId.c_str(), strName.substr(posId + 1).c_str()) != 0) {
            COMM_LOGE(COMM_SVC, "appId is different from session name");
            return SOFTBUS_STRCMP_ERR;
        }
        strName.erase(posId);
    }
    return SOFTBUS_OK;
}
#endif

int32_t SoftBusServerStub::CreateSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "CreateSessionServerInner read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }

    const char *sessionName = data.ReadCString();
    std::string strName;
    uint32_t code = SERVER_CREATE_SESSION_SERVER;
    SoftbusRecordCalledApiInfo(pkgName, code);
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
        goto EXIT;
    }
    strName = sessionName;
    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
#ifdef SUPPORT_BUNDLENAME
    if (CheckNormalAppSessionName(sessionName, callingUid, strName) != SOFTBUS_OK) {
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }
    sessionName = strName.c_str();
#endif
    retReply = CreateSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "CreateSessionServerInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemoveSessionServerInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t retReply;
    pid_t callingUid;
    pid_t callingPid;
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }

    const char *sessionName = data.ReadCString();
    uint32_t code = SERVER_REMOVE_SESSION_SERVER;
    SoftbusRecordCalledApiInfo(pkgName, code);
    if (pkgName == nullptr || sessionName == nullptr) {
        retReply = SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
        goto EXIT;
    }

    callingUid = OHOS::IPCSkeleton::GetCallingUid();
    callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (CheckTransPermission(callingUid, callingPid, pkgName, sessionName, ACTION_CREATE) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner check perm failed");
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }

    if (!CheckUidAndPid(sessionName, callingUid, callingPid)) {
        COMM_LOGE(COMM_SVC, "Check Uid and Pid failed!");
        return SOFTBUS_TRANS_CHECK_PID_ERROR;
    }
    retReply = RemoveSessionServer(pkgName, sessionName);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "RemoveSessionServerInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
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

    if (getAttr->linkTypeNum > 0 && getAttr->linkTypeNum <= LINK_TYPE_MAX) {
        pGetArr = const_cast<LinkType *>(
            reinterpret_cast<const LinkType *>(data.ReadBuffer(sizeof(LinkType) * getAttr->linkTypeNum)));
    }

    if (pGetArr != nullptr) {
        if (memcpy_s(getAttr->linkType, sizeof(LinkType) * LINK_TYPE_MAX, pGetArr,
            sizeof(LinkType) * getAttr->linkTypeNum) != EOK) {
            COMM_LOGE(COMM_SVC, "LinkType copy failed linkTypeNum = %{public}d, dataType = %{public}d",
                getAttr->linkTypeNum, getAttr->dataType);
        }
    }

    getAttr->attr.streamAttr.streamType = data.ReadInt32();
    getAttr->fastTransDataSize = data.ReadUint16();
    if (getAttr->fastTransDataSize != 0) {
        getAttr->fastTransData =
            const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(data.ReadRawData(getAttr->fastTransDataSize)));
    }
}

static bool ReadQosInfo(MessageParcel &data, SessionParam &param)
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

static void ReadSessionInfo(MessageParcel &data, SessionParam &param)
{
    param.sessionName = data.ReadCString();
    param.peerSessionName = data.ReadCString();
    param.peerDeviceId = data.ReadCString();
    param.groupId = data.ReadCString();
    param.isAsync = data.ReadBool();
    param.sessionId = data.ReadInt32();
    param.actionId = data.ReadUint32();
    param.pid = OHOS::IPCSkeleton::GetCallingPid();
}

int32_t SoftBusServerStub::OpenSessionInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t retReply;
    SessionParam param { 0 };
    SessionAttribute getAttr { 0 };

    TransSerializer transSerializer;
    int64_t timeStart = 0;
    int64_t timediff = 0;
    SoftBusOpenSessionStatus isSucc = SOFTBUS_EVT_OPEN_SESSION_FAIL;
    ReadSessionInfo(data, param);
    ReadSessionAttrs(data, &getAttr);
    param.attr = &getAttr;
    COMM_CHECK_AND_RETURN_RET_LOGE(ReadQosInfo(data, param), SOFTBUS_IPC_ERR, COMM_SVC, "failed to read qos info");

    if (param.sessionName == nullptr || param.peerSessionName == nullptr || param.peerDeviceId == nullptr ||
        param.groupId == nullptr) {
        retReply = SOFTBUS_INVALID_PARAM;
        goto EXIT;
    }
    if ((retReply = TransCheckClientAccessControl(param.peerDeviceId)) != SOFTBUS_OK) {
        goto EXIT;
    }
    if (CheckOpenSessionPermission(&param) != SOFTBUS_OK) {
        SoftbusReportTransErrorEvt(SOFTBUS_PERMISSION_DENIED);
        retReply = SOFTBUS_PERMISSION_DENIED;
        goto EXIT;
    }

    timeStart = GetSoftbusRecordTimeMillis();
    retReply = OpenSession(&param, &(transSerializer.transInfo));
    timediff = GetSoftbusRecordTimeMillis() - timeStart;

    isSucc = (retReply == SOFTBUS_OK) ? SOFTBUS_EVT_OPEN_SESSION_SUCC : SOFTBUS_EVT_OPEN_SESSION_FAIL;
    SoftbusRecordOpenSession(isSucc, static_cast<uint32_t>(timediff));

EXIT:
    transSerializer.ret = retReply;
    bool result = reply.WriteRawData(&transSerializer, sizeof(TransSerializer));
    COMM_CHECK_AND_RETURN_RET_LOGE(result, SOFTBUS_IPC_ERR, COMM_SVC, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::OpenAuthSessionInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t retReply;
    const char *sessionName = data.ReadCString();
    ConnectionAddr *addrInfo = const_cast<ConnectionAddr *>(
        reinterpret_cast<const ConnectionAddr *>(data.ReadRawData(sizeof(ConnectionAddr))));
    if (sessionName == nullptr || addrInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "OpenAuthSessionInner get param failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    SessionParam param;
    param.sessionName = sessionName;
    param.peerSessionName = sessionName;
    retReply = CheckOpenSessionPermission(&param);
    if (retReply != SOFTBUS_OK) {
        goto EXIT;
    }
    retReply = OpenAuthSession(sessionName, addrInfo);
    AddChannelStatisticsInfo(retReply, CHANNEL_TYPE_AUTH);
    COMM_LOGI(COMM_SVC, "OpenAuthSession channelId=%{public}d", retReply);
EXIT:
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "OpenSessionInner write reply failed! retReply=%{public}d", retReply);
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::NotifyAuthSuccessInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t channelId;
    int32_t channelType;
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner read channel Id failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner read channel type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t ret = TransGetAndComparePid(callingPid, channelId, channelType);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "callingPid not equal pid, callingPid=%{public}d, channelId=%{public}d",
            callingPid, channelId);
        return ret;
    }
    int32_t retReply = NotifyAuthSuccess(channelId, channelType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "NotifyAuthSuccessInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ReleaseResourcesInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "failed to read channel Id");
        return SOFTBUS_IPC_ERR;
    }

    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    int32_t ret = TransGetAndComparePid(callingPid, channelId, CHANNEL_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "Pid not find, ret = %{public}d", ret);
        if (!reply.WriteInt32(ret)) {
            COMM_LOGE(COMM_SVC, "failed to write ret failed");
            return SOFTBUS_IPC_ERR;
        }
        return ret;
    }
    int32_t retReply = ReleaseResources(channelId);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "failed to write reply failed");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CloseChannelInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner read channel Id failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner read channel channel type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    const char *sessionName = nullptr;
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (channelType == CHANNEL_TYPE_UNDEFINED) {
        sessionName = data.ReadCString();
        if (sessionName == nullptr) {
            COMM_LOGE(COMM_SVC, "CloseChannelInner get param failed!");
            return SOFTBUS_IPC_ERR;
        }
        int32_t ret = TransGetAndComparePidBySession(callingPid, sessionName, channelId);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_SVC, "Pid can not close channel, pid=%{public}d, sessionId=%{public}d, ret=%{public}d",
                callingPid, channelId, ret);
            return ret;
        }
    } else {
        int32_t ret = TransGetAndComparePid(callingPid, channelId, channelType);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_SVC, "Pid can not close channel, pid=%{public}d, channelId=%{public}d, ret=%{public}d",
                callingPid, channelId, ret);
            return ret;
        }
    }

    int32_t retReply = CloseChannel(sessionName, channelId, channelType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::CloseChannelWithStatisticsInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "CloseChannelWithStatisticsInner read channel id failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "CloseChannelWithStatisticsInner read channel type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    uint64_t laneId;
    if (!data.ReadUint64(laneId)) {
        COMM_LOGE(COMM_SVC, "CloseChannelWithStatisticsInner read lane id failed!");
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SVC, "CloseChannelWithStatisticsInner dataInfo len failed!");
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }

    auto rawData = data.ReadRawData(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(rawData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read len failed.");
    void *dataInfo = const_cast<void *>(rawData);

    int32_t retReply = CloseChannelWithStatistics(channelId, channelType, laneId, dataInfo, len);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "CloseChannelInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SendMessageInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "SendMessage read channel Id failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "SendMessage read channel type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    uint32_t len;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SVC, "SendMessage dataInfo len failed!");
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }

    auto rawData = data.ReadRawData(len);
    COMM_CHECK_AND_RETURN_RET_LOGE(rawData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read rawData failed!");
    void *dataInfo = const_cast<void *>(rawData);

    int32_t msgType;
    if (!data.ReadInt32(msgType)) {
        COMM_LOGE(COMM_SVC, "SendMessage message type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    if (TransGetAndComparePid(callingPid, channelId, channelType) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "pid permission check failed!");
        return SOFTBUS_PERMISSION_DENIED;
    }

    int32_t retReply = SendMessage(channelId, channelType, dataInfo, len, msgType);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SendMessage write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::EvaluateQosInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
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
    COMM_LOGD(COMM_SVC, "enter");
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

    auto rawData = data.ReadRawData(addrTypeLen);
    COMM_CHECK_AND_RETURN_RET_LOGE(rawData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read addrTypeLen failed.");
    void *addr = const_cast<void *>(rawData);

    int32_t retReply = JoinLNN(clientName, addr, addrTypeLen);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SoftbusJoinLNNInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::LeaveLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
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
    COMM_LOGD(COMM_SVC, "enter");
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
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
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

    infoTypeLen = data.ReadUint32();
    if (infoTypeLen != sizeof(NodeBasicInfo)) {
        COMM_LOGE(COMM_SVC, "read infoTypeLen failed!");
        return SOFTBUS_IPC_ERR;
    }
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

int32_t SoftBusServerStub::GetNodeKeyInfoInner(MessageParcel &data, MessageParcel &reply)
{
    const char *clientName = data.ReadCString();
    const char *networkId = data.ReadCString();
    if (clientName == nullptr || networkId == nullptr) {
        COMM_LOGE(COMM_SVC, "read clientName or networkId failed!");
        return SOFTBUS_IPC_ERR;
    }
    char *anonyNetworkId = nullptr;
    Anonymize(networkId, &anonyNetworkId);
    COMM_LOGD(COMM_SVC, "networkId=%{public}s", anonyNetworkId);
    AnonymizeFree(anonyNetworkId);

    int32_t key;
    READ_PARCEL_WITH_RET(data, Int32, key, SOFTBUS_IPC_ERR);
    int32_t infoLen = GetNodeKeyInfoLen(key);
    if (infoLen == SOFTBUS_ERR) {
        COMM_LOGE(COMM_SVC, "get info len failed!");
        return SOFTBUS_NETWORK_NODE_KEY_INFO_ERR;
    }
    uint32_t len;
    READ_PARCEL_WITH_RET(data, Uint32, len, SOFTBUS_IPC_ERR);
    if (len < (uint32_t)infoLen) {
        COMM_LOGE(COMM_SVC, "invalid param, len=%{public}u, infoLen=%{public}d", len, infoLen);
        return SOFTBUS_INVALID_PARAM;
    }
    void *buf = SoftBusCalloc(infoLen);
    if (buf == nullptr) {
        COMM_LOGE(COMM_SVC, "malloc buffer failed!");
        return SOFTBUS_MALLOC_ERR;
    }
    if (GetNodeKeyInfo(clientName, networkId, key, static_cast<unsigned char *>(buf), infoLen) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get key info failed!");
        SoftBusFree(buf);
        return SOFTBUS_NETWORK_NODE_KEY_INFO_ERR;
    }
    if (!reply.WriteInt32(infoLen)) {
        COMM_LOGE(COMM_SVC, "write info length failed!");
        SoftBusFree(buf);
        return SOFTBUS_IPC_ERR;
    }
    if (!reply.WriteRawData(buf, infoLen)) {
        COMM_LOGE(COMM_SVC, "write key info failed!");
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
    uint16_t changeFlag;
    if (!data.ReadUint16(changeFlag)) {
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

int32_t SoftBusServerStub::RegDataLevelChangeCbInner(MessageParcel &data, MessageParcel &reply)
{
#ifndef ENHANCED_FLAG
    (void)data;
    (void)reply;
    (void)DB_PACKAGE_NAME;
    return SOFTBUS_FUNC_NOT_SUPPORT;
#else
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "RegDataLevelChangeCbInner read pkgName failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (strcmp(DB_PACKAGE_NAME, pkgName) != 0) {
        COMM_LOGE(COMM_SVC, "RegDataLevelChangeCbInner read pkgName invalid!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = RegDataLevelChangeCb(pkgName);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "RegDataLevelChangeCbInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
#endif
}

int32_t SoftBusServerStub::UnregDataLevelChangeCbInner(MessageParcel &data, MessageParcel &reply)
{
#ifndef ENHANCED_FLAG
    (void)data;
    (void)reply;
    (void)DB_PACKAGE_NAME;
    return SOFTBUS_FUNC_NOT_SUPPORT;
#else
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr) {
        COMM_LOGE(COMM_SVC, "UnregDataLevelChangeCbInner read pkgName failed!");
        return SOFTBUS_IPC_ERR;
    }
    if (strcmp(DB_PACKAGE_NAME, pkgName) != 0) {
        COMM_LOGE(COMM_SVC, "UnregDataLevelChangeCbInner read pkgName invalid!");
        return SOFTBUS_IPC_ERR;
    }
    int32_t retReply = UnregDataLevelChangeCb(pkgName);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "UnregDataLevelChangeCbInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
#endif
}

int32_t SoftBusServerStub::SetDataLevelInner(MessageParcel &data, MessageParcel &reply)
{
#ifndef ENHANCED_FLAG
    (void)data;
    (void)reply;
    return SOFTBUS_FUNC_NOT_SUPPORT;
#else
    DataLevel *dataLevel = (DataLevel*)data.ReadRawData(sizeof(DataLevel));
    if (dataLevel == nullptr) {
        COMM_LOGE(COMM_SVC, "SetDataLevelInner read networkid failed!");
        return SOFTBUS_IPC_ERR;
    }

    int32_t retReply = SetDataLevel(dataLevel);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "SetDataLevelInner write reply failed!");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
#endif
}

int32_t SoftBusServerStub::StartTimeSyncInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
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
    COMM_LOGD(COMM_SVC, "enter");
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
    COMM_LOGD(COMM_SVC, "enter");
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel Id failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel channel type failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t appType;
    if (!data.ReadInt32(appType)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read channel appType failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t quality;
    if (!data.ReadInt32(quality)) {
        COMM_LOGE(COMM_SVC, "QosReportInner read quality failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    int32_t ret = TransGetAndComparePid(callingPid, channelId, channelType);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "Pid can not get qos report, pid=%{public}d, channelId=%{public}d, ret=%{public}d",
            callingPid, channelId, ret);
        return ret;
    }
    int32_t retReply = QosReport(channelId, channelType, appType, quality);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "QosReportInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StreamStatsInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner read channelId fail");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner read channelType fail");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    StreamSendStats *stats = const_cast<StreamSendStats *>(
        reinterpret_cast<const StreamSendStats *>(data.ReadRawData(sizeof(StreamSendStats))));
    if (stats == nullptr) {
        COMM_LOGE(COMM_SVC, "read StreamSendStats fail, stats is nullptr");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    int32_t ret = TransGetAndComparePid(callingPid, channelId, channelType);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "Pid can not get stream stats, pid=%{public}d, channelId=%{public}d, ret=%{public}d",
            callingPid, channelId, ret);
        return ret;
    }
    int32_t retReply = StreamStats(channelId, channelType, stats);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "StreamStatsInner write reply fail");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RippleStatsInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t channelId;
    if (!data.ReadInt32(channelId)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner read channelId fail");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t channelType;
    if (!data.ReadInt32(channelType)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner read channelType fail");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    TrafficStats *stats =
        const_cast<TrafficStats *>(reinterpret_cast<const TrafficStats *>(data.ReadRawData(sizeof(TrafficStats))));
    if (stats == nullptr) {
        COMM_LOGE(COMM_SVC, "read rippleStats fail, stats is nullptr");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    int32_t ret = TransGetAndComparePid(callingPid, channelId, channelType);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "Pid can not get pipple stats, pid=%{public}d, channelId=%{public}d, ret=%{public}d",
            callingPid, channelId, ret);
        return ret;
    }
    int32_t retReply = RippleStats(channelId, channelType, stats);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "rippleStatsInner write reply fail");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GrantPermissionInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t uid = 0;
    int32_t pid = 0;
    const char *sessionName = nullptr;
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = SoftBusCheckDynamicPermission(callingTokenId);
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
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RemovePermissionInner(MessageParcel &data, MessageParcel &reply)
{
    const char *sessionName = nullptr;
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = SoftBusCheckDynamicPermission(callingTokenId);
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
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(clientName != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read clientName failed");

    PublishInfo info = {0};
    int32_t value = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(info.publishId), SOFTBUS_IPC_ERR, COMM_SVC,
        "read publishId failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read mode failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(value == DISCOVER_MODE_PASSIVE || value == DISCOVER_MODE_ACTIVE,
        SOFTBUS_INVALID_PARAM, COMM_SVC, "mode invalid");
    info.mode = static_cast<DiscoverMode>(value);
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read medium failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(0 <= value && value < MEDIUM_BUTT, SOFTBUS_INVALID_PARAM, COMM_SVC,
        "medium invalid");
    info.medium = static_cast<ExchangeMedium>(value);
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read freq failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(0 <= value && value < FREQ_BUTT, SOFTBUS_INVALID_PARAM, COMM_SVC, "freq invalid");
    info.freq = static_cast<ExchangeFreq>(value);

    info.capability = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(info.capability != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read capability failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadUint32(info.dataLen), SOFTBUS_IPC_ERR, COMM_SVC, "read dataLen failed");
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        const char *capabilityData = data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(capabilityData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read capaData failed");
        COMM_CHECK_AND_RETURN_RET_LOGE(strlen(capabilityData) == info.dataLen, SOFTBUS_INVALID_PARAM, COMM_SVC,
            "capabilityData invalid");
        info.capabilityData = const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(capabilityData));
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadBool(info.ranging), SOFTBUS_IPC_ERR, COMM_SVC, "read ranging failed");

    int32_t retReply = PublishLNN(clientName, &info);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(retReply), SOFTBUS_IPC_ERR, COMM_SVC, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopPublishLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(clientName != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read clientName failed");

    int32_t publishId = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(publishId), SOFTBUS_IPC_ERR, COMM_SVC, "read publishId failed");

    int32_t retReply = StopPublishLNN(clientName, publishId);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(retReply), SOFTBUS_IPC_ERR, COMM_SVC, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::RefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(clientName != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read clientName failed");

    SubscribeInfo info = {0};
    int32_t value = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(info.subscribeId), SOFTBUS_IPC_ERR, COMM_SVC,
        "read subscribeId failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read mode failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(value == DISCOVER_MODE_PASSIVE || value == DISCOVER_MODE_ACTIVE,
        SOFTBUS_INVALID_PARAM, COMM_SVC, "mode invalid");
    info.mode = static_cast<DiscoverMode>(value);
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read medium failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(0 <= value && value < MEDIUM_BUTT, SOFTBUS_INVALID_PARAM, COMM_SVC,
        "medium invalid");
    info.medium = static_cast<ExchangeMedium>(value);
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(value), SOFTBUS_IPC_ERR, COMM_SVC, "read freq failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(0 <= value && value < FREQ_BUTT, SOFTBUS_INVALID_PARAM, COMM_SVC, "freq invalid");
    info.freq = static_cast<ExchangeFreq>(value);
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadBool(info.isSameAccount), SOFTBUS_IPC_ERR, COMM_SVC,
        "read isSameAccount failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadBool(info.isWakeRemote), SOFTBUS_IPC_ERR, COMM_SVC,
        "read isWakeRemote failed");

    info.capability = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(info.capability != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read capability failed");
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadUint32(info.dataLen), SOFTBUS_IPC_ERR, COMM_SVC, "read dataLen failed");
    if (info.dataLen > 0 && info.dataLen < MAX_CAPABILITYDATA_LEN) {
        const char *capabilityData = data.ReadCString();
        COMM_CHECK_AND_RETURN_RET_LOGE(capabilityData != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read capaData failed");
        COMM_CHECK_AND_RETURN_RET_LOGE(strlen(capabilityData) == info.dataLen, SOFTBUS_INVALID_PARAM, COMM_SVC,
            "capabilityData invalid");
        info.capabilityData = const_cast<unsigned char *>(reinterpret_cast<const unsigned char *>(capabilityData));
    } else {
        info.capabilityData = nullptr;
        info.dataLen = 0;
    }

    int32_t retReply = RefreshLNN(clientName, &info);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(retReply), SOFTBUS_IPC_ERR, COMM_SVC, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::StopRefreshLNNInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    const char *clientName = data.ReadCString();
    COMM_CHECK_AND_RETURN_RET_LOGE(clientName != nullptr, SOFTBUS_IPC_ERR, COMM_SVC, "read clientName failed");

    int32_t refreshId = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(data.ReadInt32(refreshId), SOFTBUS_IPC_ERR, COMM_SVC, "read refreshId failed");

    int32_t retReply = StopRefreshLNN(clientName, refreshId);
    COMM_CHECK_AND_RETURN_RET_LOGE(reply.WriteInt32(retReply), SOFTBUS_IPC_ERR, COMM_SVC, "write reply failed");
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ActiveMetaNodeInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    MetaNodeConfigInfo *info = const_cast<MetaNodeConfigInfo *>(
        reinterpret_cast<const MetaNodeConfigInfo *>(data.ReadRawData(sizeof(MetaNodeConfigInfo))));
    if (info == nullptr) {
        COMM_LOGE(COMM_SVC, "ActiveMetaNode read meta node config info failed!");
        return SOFTBUS_IPC_ERR;
    }
    char metaNodeId[NETWORK_ID_BUF_LEN] = { 0 };
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
    COMM_LOGD(COMM_SVC, "enter");
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
    COMM_LOGD(COMM_SVC, "enter");
    int32_t infoNum;
    MetaNodeInfo infos[MAX_META_NODE_NUM];

    if (!data.ReadInt32(infoNum)) {
        COMM_LOGE(COMM_SVC, "GetAllMetaNodeInfo read infoNum failed!");
        return SOFTBUS_IPC_ERR;
    }
    if ((uint32_t)infoNum > MAX_META_NODE_NUM) {
        COMM_LOGE(COMM_SVC, "invalid param, infoNum=%{public}d, maxNum=%{public}d", infoNum, MAX_META_NODE_NUM);
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
    COMM_LOGD(COMM_SVC, "enter");
    const char *targetNetworkId = nullptr;
    const GearMode *mode = nullptr;

    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strnlen(pkgName, PKG_NAME_SIZE_MAX) >= PKG_NAME_SIZE_MAX) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED;
    }
    uint32_t code = SERVER_SHIFT_LNN_GEAR;
    SoftbusRecordCalledApiInfo(pkgName, code);
    const char *callerId = data.ReadCString();
    if (callerId == nullptr || strnlen(callerId, CALLER_ID_MAX_LEN) >= CALLER_ID_MAX_LEN) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read callerId failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    if (!data.ReadBool()) {
        targetNetworkId = data.ReadCString();
        if (targetNetworkId == nullptr || strnlen(targetNetworkId, NETWORK_ID_BUF_LEN) != NETWORK_ID_BUF_LEN - 1) {
            COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read targetNetworkId failed!");
            return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
        }
    }
    mode = reinterpret_cast<const GearMode *>(data.ReadRawData(sizeof(GearMode)));
    if (mode == nullptr) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner read mode failed!");
        return SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED;
    }
    int32_t retReply = ShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "ShiftLNNGearInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SyncTrustedRelationShipInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");

    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strnlen(pkgName, PKG_NAME_SIZE_MAX) >= PKG_NAME_SIZE_MAX) {
        COMM_LOGE(COMM_SVC, "read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    if (strcmp(DM_PACKAGE_NAME, pkgName) != 0) {
        COMM_LOGE(COMM_SVC, "read pkgName invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusRecordCalledApiInfo(pkgName, SERVER_SYNC_TRUSTED_RELATION);
    const char *msg = data.ReadCString();
    if (msg == nullptr) {
        COMM_LOGE(COMM_SVC, "read msg failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    uint32_t msgLen = data.ReadUint32();
    if (msgLen > MSG_MAX_SIZE || msgLen != strlen(msg)) {
        COMM_LOGE(COMM_SVC, "msgLen invalid!, msgLen=%{public}u", msgLen);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t retReply = SyncTrustedRelationShip(pkgName, msg, msgLen);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "write reply failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::GetSoftbusSpecObjectInner(MessageParcel &data, MessageParcel &reply)
{
    sptr<IRemoteObject> object;
    int32_t ret = GetSoftbusSpecObject(object);
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "GetSoftbusSpecObjectInner write reply failed!");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (ret == SOFTBUS_OK) {
        if (!reply.WriteRemoteObject(object)) {
            COMM_LOGE(COMM_SVC, "GetSoftbusSpecObjectInner write object failed!");
            return SOFTBUS_TRANS_PROXY_WRITEOBJECT_FAILED;
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
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    if (ret == SOFTBUS_OK) {
        if (!reply.WriteRemoteObject(object)) {
            COMM_LOGE(COMM_SVC, "GetBusCenterExObjInner write object failed!");
            return SOFTBUS_TRANS_PROXY_WRITEOBJECT_FAILED;
        }
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::ProcessInnerEventInner(MessageParcel &data, MessageParcel &reply)
{
    int32_t eventType = 0;
    if (!data.ReadInt32(eventType)) {
        COMM_LOGE(COMM_SVC, "read eventType failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    uint32_t len = 0;
    if (!data.ReadUint32(len)) {
        COMM_LOGE(COMM_SVC, "read len failed!");
        return SOFTBUS_TRANS_PROXY_READUINT_FAILED;
    }
    auto rawData = data.ReadRawData(len);
    if (rawData == NULL) {
        COMM_LOGE(COMM_SVC, "read rawData failed!");
        return SOFTBUS_IPC_ERR;
    }
    uint8_t *buf = const_cast<uint8_t *>(reinterpret_cast<const uint8_t *>(rawData));
    int32_t ret = ProcessInnerEvent(eventType, buf, len);
    COMM_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, COMM_SVC, "process inner event failed! eventType=%{public}d", eventType);
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::PrivilegeCloseChannelInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    int32_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    if (callingUid != DMS_CALLING_UID) {
        COMM_LOGE(COMM_PERM, "uid check failed");
        return SOFTBUS_PERMISSION_DENIED;
    }
    uint64_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = SoftBusCheckDmsServerPermission(callingTokenId);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "check permission failed. ret=%{public}d", ret);
        if (!reply.WriteInt32(ret)) {
            COMM_LOGE(COMM_SVC, "write reply failed!");
            return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
        }
        return ret;
    }
    uint64_t tokenId;
    if (!data.ReadUint64(tokenId)) {
        COMM_LOGE(COMM_SVC, "read tokenId failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    int32_t pid;
    if (!data.ReadInt32(pid)) {
        COMM_LOGE(COMM_SVC, "read pid failed!");
        return SOFTBUS_TRANS_PROXY_READINT_FAILED;
    }
    const char *peerNetworkId = data.ReadCString();
    if (peerNetworkId == nullptr) {
        COMM_LOGE(COMM_SVC, "network id is null!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    ret = PrivilegeCloseChannel(tokenId, pid, peerNetworkId);
    if (!reply.WriteInt32(ret)) {
        COMM_LOGE(COMM_SVC, "write reply failed, ret=%{public}d", ret);
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServerStub::SetDisplayNameInner(MessageParcel &data, MessageParcel &reply)
{
    COMM_LOGD(COMM_SVC, "enter");
    const char *pkgName = data.ReadCString();
    if (pkgName == nullptr || strnlen(pkgName, PKG_NAME_SIZE_MAX) >= PKG_NAME_SIZE_MAX) {
        COMM_LOGE(COMM_SVC, "read pkgName failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    if (strcmp(DM_PACKAGE_NAME, pkgName) != 0) {
        COMM_LOGE(COMM_SVC, "read pkgName invalid!");
        return SOFTBUS_INVALID_PARAM;
    }
    SoftbusRecordCalledApiInfo(pkgName, SERVER_SET_DISPLAY_NAME);
    const char *nameData = data.ReadCString();
    if (nameData == nullptr) {
        COMM_LOGE(COMM_SVC, "read nameData failed!");
        return SOFTBUS_TRANS_PROXY_READCSTRING_FAILED;
    }
    uint32_t len = data.ReadUint32();
    if (len > MSG_MAX_SIZE || len != strlen(nameData)) {
        COMM_LOGE(COMM_SVC, "len invalid!, len=%{public}u", len);
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t retReply = SetDisplayName(pkgName, nameData, len);
    if (!reply.WriteInt32(retReply)) {
        COMM_LOGE(COMM_SVC, "write reply failed");
        return SOFTBUS_TRANS_PROXY_WRITEINT_FAILED;
    }
    return SOFTBUS_OK;
}

} // namespace OHOS
