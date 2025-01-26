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

#include "softbus_server.h"

#include "bus_center_ex_obj.h"
#include "ipc_skeleton.h"
#include "lnn_bus_center_ipc.h"
#include "securec.h"
#include "string_ex.h"
#include "softbus_client_info_manager.h"
#include "softbus_disc_server.h"
#include "legacy/softbus_hidumper_interface.h"
#include "softbus_server_death_recipient.h"
#include "softbus_server_frame.h"
#include "softbus_utils.h"
#include "system_ability_definition.h"
#include "trans_channel_manager.h"
#include "trans_session_service.h"
#include "trans_spec_object.h"
#include "lnn_lane_interface.h"

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

int32_t SoftBusServer::CreateSessionServer(const char *pkgName, const char *sessionName)
{
    pid_t callingUid = OHOS::IPCSkeleton::GetCallingUid();
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return TransCreateSessionServer(pkgName, sessionName, (int32_t)callingUid, (int32_t)callingPid);
}

int32_t SoftBusServer::RemoveSessionServer(const char *pkgName, const char *sessionName)
{
    return TransRemoveSessionServer(pkgName, sessionName);
}

int32_t SoftBusServer::OpenSession(const SessionParam *param, TransInfo *info)
{
    return TransOpenSession(param, info);
}

int32_t SoftBusServer::OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo)
{
    if (sessionName == nullptr || addrInfo == nullptr) {
        COMM_LOGE(COMM_SVC, "session name or addrinfo is nullptr");
        return SOFTBUS_INVALID_PARAM;
    }
    ConnectOption connOpt;
    (void)memset_s(&connOpt, sizeof(ConnectOption), 0, sizeof(ConnectOption));
    connOpt.type = ConvertConnectType(addrInfo->type);
    switch (connOpt.type) {
        case CONNECT_TCP:
            if (memcpy_s(connOpt.socketOption.addr, sizeof(connOpt.socketOption.addr), addrInfo->info.ip.ip, IP_LEN) !=
                EOK) {
                COMM_LOGE(COMM_SVC, "connect TCP memory error");
                return SOFTBUS_MEM_ERR;
            }
            connOpt.socketOption.port = static_cast<int32_t>(addrInfo->info.ip.port);
            connOpt.socketOption.protocol = LNN_PROTOCOL_IP;
            connOpt.socketOption.moduleId = AUTH;
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
            break;
        case CONNECT_BR:
            if (memcpy_s(connOpt.brOption.brMac, BT_MAC_LEN, addrInfo->info.br.brMac, BT_MAC_LEN) != EOK) {
                COMM_LOGE(COMM_SVC, "connect BR memory error");
                return SOFTBUS_MEM_ERR;
            }
            connOpt.brOption.waitTimeoutDelay = OPEN_AUTH_BR_CONNECT_TIMEOUT_MILLIS;
            break;
        default:
            COMM_LOGE(COMM_SVC, "connect type error");
            return SOFTBUS_TRANS_INVALID_CONNECT_TYPE;
    }
    return TransOpenAuthChannel(sessionName, &connOpt, "");
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

int32_t SoftBusServer::JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen)
{
    pid_t callingPid = OHOS::IPCSkeleton::GetCallingPid();
    return LnnIpcServerJoin(pkgName, (int32_t)callingPid, addr, addrTypeLen);
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

int32_t SoftBusServer::GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
    uint32_t len)
{
    return LnnIpcGetNodeKeyInfo(pkgName, networkId, key, buf, len);
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
    return LnnIpcPublishLNN(pkgName, info);
}

int32_t SoftBusServer::StopPublishLNN(const char *pkgName, int32_t publishId)
{
    return LnnIpcStopPublishLNN(pkgName, publishId);
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

    int argc = (int)argsStr.size();
    const char *argv[argc];

    for (int i = 0; i < argc; i++) {
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
} // namespace OHOS
