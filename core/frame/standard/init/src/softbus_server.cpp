/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#include "softbus_server.h"

#include "br_proxy_server_manager.h"
#include "bus_center_ex_obj.h"
#include "ipc_skeleton.h"
#include "lnn_bus_center_ipc.h"
#include "securec.h"
#include "string_ex.h"
#include "softbus_client_info_manager.h"
#include "legacy/softbus_hidumper_interface.h"
#include "softbus_server_death_recipient.h"
#include "softbus_server_frame.h"
#include "softbus_utils.h"
#include "system_ability_definition.h"
#include "trans_channel_manager.h"
#include "trans_session_service.h"
#include "trans_spec_object.h"
#include "lnn_lane_interface.h"
#include "general_connection_client_proxy.h"
#include "softbus_conn_general_connection.h"

#ifdef SUPPORT_BUNDLENAME
#include "bundle_mgr_proxy.h"
#include "iservice_registry.h"
#include "system_ability_definition.h"
#endif

#define SOFTBUS_IPC_THREAD_NUM 32
#define OPEN_AUTH_BR_CONNECT_TIMEOUT_MILLIS (15 * 1000)

namespace OHOS {
REGISTER_SYSTEM_ABILITY_BY_ID(SoftBusServer, SOFTBUS_SERVER_SA_ID, true);

static ConnectType ConvertConnectType(ConnectionAddrType type)
{
    switch (type) {
        case CONNECTION_ADDR_BR:
            return CONNECT_BR;
        case CONNECTION_ADDR_BLE:
            return CONNECT_BLE;
        case CONNECTION_ADDR_ETH:
            return CONNECT_TCP;
        case CONNECTION_ADDR_WLAN:
        case CONNECTION_ADDR_NCM:
            return CONNECT_TCP;
        default:
            return CONNECT_TYPE_MAX;
    }
}

SoftBusServer::SoftBusServer(int32_t saId, bool runOnCreate) : SystemAbility(saId, runOnCreate)
{
}

int32_t SoftBusServer::SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object)
{
    if (clientPkgName == nullptr || object == nullptr) {
        COMM_LOGE(COMM_SVC, "package name or object is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t pid = (int32_t)(OHOS::IPCSkeleton::GetCallingPid());
    if (SoftbusClientInfoManager::GetInstance().SoftbusClientIsExist(clientPkgName, pid)) {
        COMM_LOGW(COMM_SVC, "softbus client is exist");
        return SOFTBUS_OK;
    }
    sptr<IRemoteObject::DeathRecipient> abilityDeath = new (std::nothrow) SoftBusDeathRecipient();
    if (abilityDeath == nullptr) {
        COMM_LOGE(COMM_SVC, "DeathRecipient object is nullptr");
        return SOFTBUS_TRANS_DEATH_RECIPIENT_INVALID;
    }
    bool ret = object->AddDeathRecipient(abilityDeath);
    if (!ret) {
        COMM_LOGE(COMM_SVC, "AddDeathRecipient failed");
        return SOFTBUS_TRANS_ADD_DEATH_RECIPIENT_FAILED;
    }
    if (SoftbusClientInfoManager::GetInstance().SoftbusAddService(clientPkgName,
        object, abilityDeath, pid) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "softbus add client service failed");
        return SOFTBUS_TRANS_ADD_CLIENT_SERVICE_FAILED;
    }
    COMM_LOGI(COMM_SVC, "softbus register service success. clientPkgName=%{public}s", clientPkgName);
    return SOFTBUS_OK;
}

int32_t SoftBusServer::CreateSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp)
{
    (void)timestamp;
    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return TransCreateSessionServer(pkgName, sessionName, (int32_t)callingUid, (int32_t)callingPid);
}

int32_t SoftBusServer::RemoveSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp)
{
    (void)timestamp;
    return TransRemoveSessionServer(pkgName, sessionName);
}

int32_t SoftBusServer::OpenSession(const SessionParam *param, TransInfo *info)
{
    return TransOpenSession(param, info);
}

static bool IsNcmAddrType(ConnectionAddrType addrType)
{
    return addrType == CONNECTION_ADDR_NCM;
}

int32_t SoftBusServer::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (sessionName == nullptr || addrInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "session name or addrinfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    ConnectParam param;
    (void)memset_s(&param, sizeof(ConnectParam), 0, sizeof(ConnectParam));
    connOpt.type = ConvertConnectType(addrInfo->type);
    switch (connOpt.type) {
        case CONNECT_TCP:
            if (memcpy_s(connOpt.socketOption.addr, sizeof(connOpt.socketOption.addr), addrInfo->info.ip.ip, IP_LEN) !=
                EOK) {
                COMM_LOGE(COMM_SVC, "connect TCP memory error");
                return SOFTBUS_MEM_ERR;
            }
            connOpt.socketOption.port = static_cast<int32_t>(addrInfo->info.ip.port);
            connOpt.socketOption.protocol = IsNcmAddrType(addrInfo->type) ? LNN_PROTOCOL_USB : LNN_PROTOCOL_IP;
            connOpt.socketOption.moduleId = IsNcmAddrType(addrInfo->type) ? AUTH_USB : AUTH;
            break;
        case CONNECT_BLE:
            if (memcpy_s(connOpt.bleOption.bleMac, BT_MAC_LEN, addrInfo->info.ble.bleMac, BT_MAC_LEN) != EOK) {
                COMM_LOGE(COMM_SVC, "connect BLE memory error");
                return SOFTBUS_MEM_ERR;
            }
            if (memcpy_s(connOpt.bleOption.deviceIdHash, sizeof(connOpt.bleOption.deviceIdHash),
                addrInfo->info.ble.udidHash, sizeof(addrInfo->info.ble.udidHash)) != EOK) {
                COMM_LOGE(COMM_SVC, "connect BLE memory error");
                return SOFTBUS_MEM_ERR;
            }
            connOpt.bleOption.protocol = addrInfo->info.ble.protocol;
            connOpt.bleOption.psm = addrInfo->info.ble.psm;
            connOpt.bleOption.fastestConnectEnable = true;
            param.blePriority = addrInfo->info.ble.priority;
            break;
        case CONNECT_BR:
            if (memcpy_s(connOpt.brOption.brMac, BT_MAC_LEN, addrInfo->info.br.brMac, BT_MAC_LEN) != EOK) {
                COMM_LOGE(COMM_SVC, "connect BR memory error");
                return SOFTBUS_MEM_ERR;
            }
            connOpt.brOption.waitTimeoutDelay = OPEN_AUTH_BR_CONNECT_TIMEOUT_MILLIS;
            connOpt.brOption.isDisableBrFrequentConnectControl = true;
            break;
        default:
            COMM_LOGE(COMM_SVC, "connect type error");
            return SOFTBUS_TRANS_INVALID_CONNECT_TYPE;
    }
    return TransOpenAuthChannel(sessionName, &connOpt, "", &param);
}

int32_t SoftBusServer::NotifyAuthSuccess(int32_t channelId, int32_t channelType)
{
    return TransNotifyAuthSuccess(channelId, channelType);
}

int32_t SoftBusServer::ReleaseResources(int32_t channelId)
{
    return TransReleaseUdpResources(channelId);
}

int32_t SoftBusServer::CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType)
{
    return TransCloseChannel(sessionName, channelId, channelType);
}

int32_t SoftBusServer::CloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
    const void *dataInfo, uint32_t len)
{
    return TransCloseChannelWithStatistics(channelId, channelType, laneId, dataInfo, len);
}

int32_t SoftBusServer::SendMessage(int32_t channelId, int32_t channelType, const void *data,
    uint32_t len, int32_t msgType)
{
    return TransSendMsg(channelId, channelType, data, len, msgType);
}

int32_t SoftBusServer::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen, bool isForceJoin)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcServerJoin(pkgName, (int32_t)callingPid, addr, addrTypeLen, isForceJoin);
}

int32_t SoftBusServer::LeaveLNN(const char *pkgName, const char *networkId)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcServerLeave(pkgName, (int32_t)callingPid, networkId);
}

int32_t SoftBusServer::GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum)
{
    return LnnIpcGetAllOnlineNodeInfo(pkgName, info, infoTypeLen, infoNum);
}

int32_t SoftBusServer::GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen)
{
    return LnnIpcGetLocalDeviceInfo(pkgName, info, infoTypeLen);
}

int32_t SoftBusServer::GetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len)
{
    return LnnIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
}

int32_t SoftBusServer::SetNodeKeyInfo(const char *pkgName, const char *networkId, int32_t key, unsigned char *buf,
    uint32_t len)
{
    return LnnIpcSetNodeKeyInfo(pkgName, networkId, key, buf, len);
}

int32_t SoftBusServer::SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag)
{
    return LnnIpcSetNodeDataChangeFlag(pkgName, networkId, dataChangeFlag);
}

int32_t SoftBusServer::RegDataLevelChangeCb(const char *pkgName)
{
    int32_t callingPid = (int32_t)OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcRegDataLevelChangeCb(pkgName, callingPid);
}

int32_t SoftBusServer::UnregDataLevelChangeCb(const char *pkgName)
{
    int32_t callingPid = (int32_t)OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcUnregDataLevelChangeCb(pkgName, callingPid);
}

int32_t SoftBusServer::SetDataLevel(const DataLevel *dataLevel)
{
    return LnnIpcSetDataLevel(dataLevel);
}

int32_t SoftBusServer::StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
    int32_t period)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcStartTimeSync(pkgName, (int32_t)callingPid, targetNetworkId, accuracy, period);
}

int32_t SoftBusServer::StopTimeSync(const char *pkgName, const char *targetNetworkId)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcStopTimeSync(pkgName, targetNetworkId, callingPid);
}

int32_t SoftBusServer::QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality)
{
    return TransRequestQos(channelId, chanType, appType, quality);
}

int32_t SoftBusServer::StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data)
{
    return TransStreamStats(channelId, channelType, data);
}

int32_t SoftBusServer::RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data)
{
    return TransRippleStats(channelId, channelType, data);
}

int32_t SoftBusServer::PublishLNN(const char *pkgName, const PublishInfo *info)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcPublishLNN(pkgName, (int32_t)callingPid, info);
}

int32_t SoftBusServer::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcStopPublishLNN(pkgName, (int32_t)callingPid, publishId);
}

int32_t SoftBusServer::RefreshLNN(const char *pkgName, const SubscribeInfo *info)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcRefreshLNN(pkgName, (int32_t)callingPid, info);
}

int32_t SoftBusServer::StopRefreshLNN(const char *pkgName, int32_t refreshId)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcStopRefreshLNN(pkgName, (int32_t)callingPid, refreshId);
}

int32_t SoftBusServer::ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId)
{
    return LnnIpcActiveMetaNode(info, metaNodeId);
}

int32_t SoftBusServer::DeactiveMetaNode(const char *metaNodeId)
{
    return LnnIpcDeactiveMetaNode(metaNodeId);
}

int32_t SoftBusServer::GetAllMetaNodeInfo(MetaNodeInfo *info, int32_t *infoNum)
{
    return LnnIpcGetAllMetaNodeInfo(info, infoNum);
}

int32_t SoftBusServer::ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
    const GearMode *mode)
{
    return LnnIpcShiftLNNGear(pkgName, callerId, targetNetworkId, mode);
}

int32_t SoftBusServer::TriggerRangeForMsdp(const char *pkgName, const RangeConfig *config)
{
    return LnnIpcTriggerRangeForMsdp(pkgName, config);
}

int32_t SoftBusServer::StopRangeForMsdp(const char *pkgName, const RangeConfig *config)
{
    return LnnIpcStopRangeForMsdp(pkgName, config);
}

int32_t SoftBusServer::RegisterRangeCallbackForMsdp(const char *pkgName)
{
    int32_t callingPid = (int32_t)OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcRegRangeCbForMsdp(pkgName, callingPid);
}

int32_t SoftBusServer::UnregisterRangeCallbackForMsdp(const char *pkgName)
{
    int32_t callingPid = (int32_t)OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcUnregRangeCbForMsdp(pkgName, callingPid);
}

int32_t SoftBusServer::SyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen)
{
    return LnnIpcSyncTrustedRelationShip(pkgName, msg, msgLen);
}

int SoftBusServer::Dump(int fd, const std::vector<std::u16string> &args)
{
    if (fd < 0) {
        COMM_LOGE(COMM_SVC, "hidumper fd is invalid");
        return SOFTBUS_INVALID_PARAM;
    }
    std::vector<std::string> argsStr;
    for (auto item : args) {
        argsStr.emplace_back(Str16ToStr8(item));
    }

    int32_t argc = (int)argsStr.size();
    const char *argv[argc];

    for (int32_t i = 0; i < argc; i++) {
        argv[i] = argsStr[i].c_str();
    }

    return SoftBusDumpProcess(fd, argc, argv);
}

void SoftBusServer::OnStart()
{
    COMM_LOGI(COMM_SVC, "SoftBusServer OnStart called!");
    InitSoftBusServer();
    if (!Publish(this)) {
        COMM_LOGE(COMM_SVC, "SoftBusServer publish failed!");
    }
    IPCSkeleton::SetMaxWorkThreadNum(SOFTBUS_IPC_THREAD_NUM);
}

void SoftBusServer::OnStop() {}

int32_t SoftBusServer::GetSoftbusSpecObject(sptr<IRemoteObject> &object)
{
    static sptr<TransSpecObject> instance = nullptr;
    static std::mutex instanceLock;
    std::lock_guard<std::mutex> autoLock(instanceLock);
    if (instance == nullptr) {
        instance = new(std::nothrow) TransSpecObject();
        if (instance == nullptr) {
            return SOFTBUS_MEM_ERR;
        }
    }
    object = instance;
    return SOFTBUS_OK;
}

int32_t SoftBusServer::GetBusCenterExObj(sptr<IRemoteObject> &object)
{
    COMM_LOGI(COMM_SVC, "SoftBusServer GetBusCenterExObj enter.");
    sptr<BusCenterExObj> result = new(std::nothrow) BusCenterExObj();
    if (result == nullptr) {
        COMM_LOGE(COMM_SVC, "SoftBusServer GetBusCenterExObj failed!");
        return SOFTBUS_MEM_ERR;
    }
    object = result;
    return SOFTBUS_OK;
}

static LaneTransType ConvertTransType(TransDataType dataType)
{
    switch (dataType) {
        case DATA_TYPE_MESSAGE:
            return LANE_T_MSG;
        case DATA_TYPE_BYTES:
            return LANE_T_BYTE;
        case DATA_TYPE_FILE:
            return LANE_T_FILE;
        case DATA_TYPE_RAW_STREAM:
            return LANE_T_RAW_STREAM;
        case DATA_TYPE_VIDEO_STREAM:
            return LANE_T_COMMON_VIDEO;
        case DATA_TYPE_AUDIO_STREAM:
            return LANE_T_COMMON_VOICE;
        case DATA_TYPE_SLICE_STREAM:
            return LANE_T_RAW_STREAM;
        default:
            return LANE_T_BUTT;
    }
}

static void ConvertQosInfo(const QosTV *qos, uint32_t qosCount, QosInfo *qosInfo)
{
    if (qos == NULL || qosCount == 0) {
        return;
    }

    for (uint32_t i = 0; i < qosCount; i++) {
        switch (qos[i].qos) {
            case QOS_TYPE_MIN_BW:
                qosInfo->minBW = qos[i].value;
                break;
            case QOS_TYPE_MAX_LATENCY:
                qosInfo->maxLaneLatency = qos[i].value;
                break;
            case QOS_TYPE_MIN_LATENCY:
                qosInfo->minLaneLatency = qos[i].value;
                break;
            default:
                break;
        }
    }
}

int32_t SoftBusServer::EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
    uint32_t qosCount)
{
    if (!IsValidString(peerNetworkId, NETWORK_ID_BUF_LEN - 1) || dataType >= DATA_TYPE_BUTT
        || qosCount > QOS_TYPE_BUTT) {
        COMM_LOGE(COMM_SVC, "SoftBusServer invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    LaneQueryInfo info;
    (void)memset_s(&info, sizeof(LaneQueryInfo), 0, sizeof(LaneQueryInfo));
    if (strcpy_s(info.networkId, NETWORK_ID_BUF_LEN, peerNetworkId) != EOK) {
        COMM_LOGE(COMM_SVC, "STRCPY fail");
        return SOFTBUS_STRCPY_ERR;
    }
    info.transType = ConvertTransType(dataType);

    QosInfo qosInfo;
    (void)memset_s(&qosInfo, sizeof(QosInfo), 0, sizeof(QosInfo));
    ConvertQosInfo(qos, qosCount, &qosInfo);
    return LnnQueryLaneResource(&info, &qosInfo);
}

int32_t SoftBusServer::ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len)
{
    return TransProcessInnerEvent(eventType, buf, len);
}

int32_t SoftBusServer::PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId)
{
    if (peerNetworkId == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }
    return TransPrivilegeCloseChannel(tokenId, pid, peerNetworkId);
}

int32_t SoftBusServer::SetDisplayName(const char *pkgName, const char *nameData, uint32_t len)
{
    return LnnIpcSetDisplayName(pkgName, nameData, len);
}

int32_t SoftBusServer::CreateGroupOwner(const char *pkgName, const struct GroupOwnerConfig *config,
    struct GroupOwnerResult *result)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcCreateGroupOwner(pkgName, (int32_t)callingPid, config, result);
}

void SoftBusServer::DestroyGroupOwner(const char *pkgName)
{
    LnnIpcDestroyGroupOwner(pkgName);
}

#ifdef SUPPORT_BUNDLENAME
static int32_t FillBundleName(char *bundleNameStr, uint32_t size)
{
    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    std::string bundleName;
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
    sptr<AppExecFwk::IBundleMgr> bundleMgr = iface_cast<AppExecFwk::IBundleMgr>(remoteObject);
    if (bundleMgr == nullptr) {
        COMM_LOGE(COMM_SVC, "iface_cast failed");
        return SOFTBUS_TRANS_GET_BUNDLE_MGR_FAILED;
    }
    if (bundleMgr->GetNameForUid(callingUid, bundleName) != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundleName failed");
        return SOFTBUS_TRANS_GET_BUNDLENAME_FAILED;
    }

    if (strcpy_s(bundleNameStr, size, bundleName.c_str()) != EOK) {
        COMM_LOGE(COMM_SVC, "copy name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}
#endif

int32_t SoftBusServer::CreateServer(const char *pkgName, const char *name)
{
    GeneralConnectionParam param = {0};
    param.pid = OHOS::IPCSkeleton::GetCallingPid();
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name) != EOK) {
        COMM_LOGE(COMM_SVC, "copy name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_SVC, "copy pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name) != EOK) {
        COMM_LOGE(COMM_SVC, "copy name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = SOFTBUS_OK;
#ifdef SUPPORT_BUNDLENAME
    ret = FillBundleName(param.bundleName, BUNDLE_NAME_MAX);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundle name failed");
        return ret;
    }
#endif
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->createServer == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    ret = manager->createServer(&param);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "createServer failed,ret=%{public}d", ret);
    }
    COMM_LOGI(COMM_SVC, "create server success");
    return ret;
}

int32_t SoftBusServer::RemoveServer(const char *pkgName, const char *name)
{
    GeneralConnectionParam param = {0};
    int32_t ret = SOFTBUS_OK;
#ifdef SUPPORT_BUNDLENAME
    ret = FillBundleName(param.bundleName, BUNDLE_NAME_MAX);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundle name failed!");
        return ret;
    }
#endif
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name) != EOK) {
        COMM_LOGE(COMM_SVC, "copy name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->closeServer == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    manager->closeServer(&param);
    COMM_LOGI(COMM_SVC, "remove server success");
    return ret;
}

int32_t SoftBusServer::Connect(const char *pkgName, const char *name, const Address *address)
{
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->connect == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    GeneralConnectionParam param = {0};
    if (strcpy_s(param.name, GENERAL_NAME_LEN, name) != EOK) {
        COMM_LOGE(COMM_SVC, "copy name failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(param.pkgName, PKG_NAME_SIZE_MAX, pkgName) != EOK) {
        COMM_LOGE(COMM_SVC, "copy pkgName failed");
        return SOFTBUS_STRCPY_ERR;
    }
#ifdef SUPPORT_BUNDLENAME
    int32_t ret = FillBundleName(param.bundleName, BUNDLE_NAME_MAX);
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get bundle name failed");
        return ret;
    }
#endif
    param.pid = OHOS::IPCSkeleton::GetCallingPid();
    int32_t handle = manager->connect(&param, address->addr.ble.mac);
    COMM_LOGI(COMM_SVC, "connect start, handle=%{public}d", handle);
    return handle;
}

int32_t SoftBusServer::Disconnect(uint32_t handle)
{
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->disconnect == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    manager->disconnect(handle, OHOS::IPCSkeleton::GetCallingPid());
    COMM_LOGI(COMM_SVC, "disconnect success, handle=%{public}d", handle);
    return SOFTBUS_OK;
}

int32_t SoftBusServer::Send(uint32_t handle, const uint8_t *data, uint32_t len)
{
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->send == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    int32_t ret = manager->send(handle, data, len, OHOS::IPCSkeleton::GetCallingPid());
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "send failed, handle=%{public}d", handle);
    }
    return ret;
}

int32_t SoftBusServer::ConnGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len)
{
    GeneralConnectionManager *manager = GetGeneralConnectionManager();
    if (manager == nullptr || manager->getPeerDeviceId == nullptr) {
        COMM_LOGE(COMM_SVC, "invalid param");
        return SOFTBUS_NO_INIT;
    }
    uint32_t callingTokenId = IPCSkeleton::GetCallingTokenID();
    int32_t ret = manager->getPeerDeviceId(handle, deviceId, len,
        callingTokenId, OHOS::IPCSkeleton::GetCallingPid());
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "get peer deviceId failed, handle=%{public}d", handle);
    }
    return ret;
}

int32_t SoftBusServer::OpenBrProxy(const char *brMac, const char *uuid)
{
    int32_t ret = TransOpenBrProxy(brMac, uuid);
    if (ret != SOFTBUS_OK) {
        TransBrProxyRemoveObject(OHOS::IPCSkeleton::GetCallingPid());
    }
    return ret;
}
 
int32_t SoftBusServer::CloseBrProxy(int32_t channelId)
{
    return TransCloseBrProxy(channelId, false);
}
 
int32_t SoftBusServer::SendBrProxyData(int32_t channelId, char *data, uint32_t dataLen)
{
    return TransSendBrProxyData(channelId, data, dataLen);
}
 
int32_t SoftBusServer::SetListenerState(int32_t channelId, int32_t type, bool CbEnabled)
{
    return TransSetListenerState(channelId, type, CbEnabled);
}
 
bool SoftBusServer::IsProxyChannelEnabled(int32_t uid)
{
    return TransIsProxyChannelEnabled(uid);
}

static int32_t PushIdentifyCheck()
{
#define PUSH_SERVICE_UID 7023
    std::string pkgName = "PUSH_SERVICE";
    sptr<IRemoteObject> clientObject = SoftbusClientInfoManager::GetInstance().GetSoftbusClientProxy(pkgName);
    if (clientObject == nullptr) {
        COMM_LOGE(COMM_SVC, "get remote object failed!");
        return SOFTBUS_TRANS_PROXY_REMOTE_NULL;
    }
    pid_t uid = IPCSkeleton::GetCallingUid();
    COMM_LOGI(COMM_SVC, "[br_proxy] uid:%{public}d", uid);
    if (uid != PUSH_SERVICE_UID) {
        pid_t pid;
        SoftbusClientInfoManager::GetInstance().SoftbusRemoveService(clientObject, pkgName, &pid);
        return SOFTBUS_TRANS_BR_PROXY_CALLER_RESTRICTED;
    }
    return SOFTBUS_OK;
}

int32_t SoftBusServer::PushRegisterHook()
{
    int32_t ret = PushIdentifyCheck();
    if (ret != SOFTBUS_OK) {
        COMM_LOGE(COMM_SVC, "[br_proxy] Push identity verification failed! ret=%{public}d", ret);
        return ret;
    }
    return TransRegisterPushHook();
}
} // namespace OHOS