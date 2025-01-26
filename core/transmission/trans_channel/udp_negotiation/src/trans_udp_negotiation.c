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

#include "trans_udp_negotiation.h"

#include "access_control.h"
#include "auth_interface.h"
#include "bus_center_event.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "securec.h"
#include "softbus_adapter_crypto.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_adapter_thread.h"
#include "softbus_adapter_timer.h"
#include "softbus_conn_interface.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_scenario_manager.h"
#include "trans_bind_request_manager.h"
#include "trans_channel_common.h"
#include "trans_channel_manager.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_lane_pending_ctl.h"
#include "trans_log.h"
#include "trans_udp_channel_manager.h"
#include "trans_udp_negotiation_exchange.h"
#include "wifi_direct_manager.h"

#define ID_NOT_USED 0
#define ID_USED 1
#define INVALID_ID (-1)
#define IVALID_SEQ (-1)
#define SEQ_OFFSET 2

#define FLAG_REQUEST 0
#define FLAG_REPLY 1
#define ID_OFFSET (1)
#define MAX_ERRDESC_LEN 128

#define ISHARE_SESSION_NAME "IShare*"
#define CLONE_SESSION_NAME "IShare_*"

static int64_t g_seq = 0;
static uint64_t g_channelIdFlagBitsMap = 0;
static IServerChannelCallBack *g_channelCb = NULL;
static SoftBusMutex g_udpNegLock;
static uint32_t g_idMark = 0;

// it's fake, gona replaced by wifi interface
const char *LOCAL_MAC_1 = "18:65";
const char *PEER_MAC_1 = "de:4f";

static int32_t GenerateUdpChannelId(void)
{
    if (SoftBusMutexLock(&g_udpNegLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate udp channel id lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    for (uint32_t id = g_idMark + 1, cnt = 0; id != g_idMark && cnt < MAX_UDP_CHANNEL_ID_COUNT; id++, cnt++) {
        id = id % MAX_UDP_CHANNEL_ID_COUNT;
        if (((g_channelIdFlagBitsMap >> id) & ID_USED) == ID_NOT_USED) {
            g_channelIdFlagBitsMap |= (ID_USED << id);
            g_idMark = id;
            SoftBusMutexUnlock(&g_udpNegLock);
            return (int32_t)id;
        }
    }
    SoftBusMutexUnlock(&g_udpNegLock);
    return INVALID_ID;
}

void ReleaseUdpChannelId(int32_t channelId)
{
    if (SoftBusMutexLock(&g_udpNegLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "release udp channel id lock failed");
        return;
    }
    uint32_t id = (uint32_t)channelId;
    if (id >= MAX_UDP_CHANNEL_ID_COUNT) {
        TRANS_LOGE(TRANS_CTRL, "id invalid, release udp channelId failed, channelId=%{public}d", channelId);
        (void)SoftBusMutexUnlock(&g_udpNegLock);
        return;
    }
    g_channelIdFlagBitsMap &= (~(ID_USED << id));
    (void)SoftBusMutexUnlock(&g_udpNegLock);
}

static int64_t GenerateSeq(bool isServer)
{
    if (SoftBusMutexLock(&g_udpNegLock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "generate seq lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    if (g_seq > INT64_MAX - SEQ_OFFSET) {
        g_seq = 0;
    }
    int64_t seq = g_seq + SEQ_OFFSET;
    g_seq += SEQ_OFFSET;
    if (isServer) {
        seq++;
    }
    SoftBusMutexUnlock(&g_udpNegLock);
    return seq;
}

static int32_t NotifyUdpChannelOpened(const AppInfo *appInfo, bool isServerSide)
{
    TRANS_LOGI(TRANS_CTRL, "enter.");
    ChannelInfo info = {0};
    char networkId[NETWORK_ID_BUF_LEN] = {0};
    info.myHandleId = appInfo->myHandleId;
    info.peerHandleId = appInfo->peerHandleId;
    info.channelId = appInfo->myData.channelId;
    info.channelType = CHANNEL_TYPE_UDP;
    info.isServer = isServerSide;
    info.businessType = appInfo->businessType;
    info.myIp = (char*)appInfo->myData.addr;
    info.sessionKey = (char*)appInfo->sessionKey;
    info.keyLen = SESSION_KEY_LENGTH;
    info.groupId = (char*)appInfo->groupId;
    info.isEncrypt = true;
    int32_t ret = LnnGetNetworkIdByUuid((const char *)appInfo->peerData.deviceId, networkId, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get network id by uuid failed.");
        return ret;
    }
    info.peerDeviceId = (char*)networkId;
    info.peerSessionName = (char*)appInfo->peerData.sessionName;
    info.routeType = (int32_t)appInfo->routeType;
    info.streamType = (int32_t)appInfo->streamType;
    info.isUdpFile = appInfo->fileProtocol == APP_INFO_UDP_FILE_PROTOCOL ? true : false;
    info.peerIp = (char*)appInfo->peerData.addr;
    if (!isServerSide) {
        info.peerPort = appInfo->peerData.port;
    }
    info.autoCloseTime = appInfo->autoCloseTime;
    info.timeStart = appInfo->timeStart;
    info.linkType = appInfo->linkType;
    info.connectType = appInfo->connectType;
    TransGetLaneIdByChannelId(appInfo->myData.channelId, &info.laneId);
    ret = g_channelCb->GetPkgNameBySessionName(appInfo->myData.sessionName,
        (char*)appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkg name fail.");
        return ret;
    }
    return g_channelCb->OnChannelOpened(appInfo->myData.pkgName, appInfo->myData.pid,
        appInfo->myData.sessionName, &info);
}

int32_t NotifyUdpChannelClosed(const AppInfo *info, int32_t messageType)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    TRANS_LOGI(TRANS_CTRL, "pkgName=%{public}s.", info->myData.pkgName);
    int32_t ret = g_channelCb->OnChannelClosed(info->myData.pkgName, info->myData.pid,
        (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP, messageType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "on channel closed failed, ret=%{public}d.", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t NotifyUdpChannelBind(const AppInfo *info)
{
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGI(TRANS_CTRL, "channelId=%{public}" PRId64, info->myData.channelId);
    int32_t ret = g_channelCb->OnChannelBind(info->myData.pkgName, info->myData.pid,
        (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "on channel bind failed, ret=%{public}d, channelId=%{public}" PRId64, ret,
            info->myData.channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t NotifyUdpChannelOpenFailed(const AppInfo *info, int32_t errCode)
{
    TRANS_LOGW(TRANS_CTRL, "enter.");
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "appInfo is null.");
        return SOFTBUS_INVALID_PARAM;
    }

    int64_t timeStart = info->timeStart;
    int64_t timediff = GetSoftbusRecordTimeMillis() - timeStart;
    char localUdid[UDID_BUF_LEN] = { 0 };
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, sizeof(localUdid));
    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = info->myData.pkgName,
        .channelId = info->myData.channelId,
        .peerNetworkId = info->peerNetWorkId,
        .socketName = info->myData.sessionName,
        .linkType = info->connectType,
        .costTime = timediff,
        .errcode = errCode,
        .osType = (info->osType < 0) ? UNKNOW_OS_TYPE : info->osType,
        .localUdid = localUdid,
        .peerUdid = info->peerUdid,
        .peerDevVer = info->peerVersion,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    extra.deviceState = TransGetDeviceState(info->peerNetWorkId);
    if (info->isClient) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }

    TransAlarmExtra extraAlarm = {
        .conflictName = NULL,
        .conflictedName = NULL,
        .occupyedName = NULL,
        .permissionName = NULL,
        .linkType = info->linkType,
        .errcode = errCode,
        .sessionName = info->myData.sessionName,
    };
    TRANS_ALARM(OPEN_SESSION_FAIL_ALARM, CONTROL_ALARM_TYPE, extraAlarm);

    SoftbusRecordOpenSessionKpi(info->myData.pkgName, info->linkType, SOFTBUS_EVT_OPEN_SESSION_FAIL, timediff);
    int ret = g_channelCb->OnChannelOpenFailed(info->myData.pkgName, info->myData.pid,
        (int32_t)(info->myData.channelId), CHANNEL_TYPE_UDP, errCode);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify udp channel open failed err.");
    }
    return ret;
}

int32_t NotifyUdpQosEvent(const AppInfo *info, int32_t eventId, int32_t tvCount, const QosTv *tvList)
{
    TRANS_LOGI(TRANS_QOS, "notify udp qos eventId=%{public}d.", eventId);
    char pkgName[PKG_NAME_SIZE_MAX] = {0};
    int32_t ret = g_channelCb->GetPkgNameBySessionName(info->myData.sessionName, pkgName, PKG_NAME_SIZE_MAX);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "get pkg name fail.");
        return ret;
    }
    QosParam param;
    param.channelId = (int32_t)(info->myData.channelId);
    param.channelType = CHANNEL_TYPE_UDP;
    param.eventId = eventId;
    param.tvCount = tvCount;
    param.tvList = tvList;
    param.pid = info->myData.pid;
    return g_channelCb->OnQosEvent(pkgName, &param);
}

static int32_t CopyAppInfoFastTransData(UdpChannelInfo *newChannel, const AppInfo *appInfo)
{
    if (appInfo->fastTransData != NULL && appInfo->fastTransDataSize > 0) {
        uint8_t *fastTransData = (uint8_t *)SoftBusCalloc(appInfo->fastTransDataSize);
        if (fastTransData == NULL) {
            return SOFTBUS_MALLOC_ERR;
        }
        if (memcpy_s((char *)fastTransData, appInfo->fastTransDataSize, (const char *)appInfo->fastTransData,
            appInfo->fastTransDataSize) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "memcpy fastTransData fail");
            SoftBusFree(fastTransData);
            return SOFTBUS_MEM_ERR;
        }
        newChannel->info.fastTransData = fastTransData;
    }
    return SOFTBUS_OK;
}

static UdpChannelInfo *NewUdpChannelByAppInfo(const AppInfo *info)
{
    UdpChannelInfo *newChannel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (newChannel == NULL) {
        TRANS_LOGE(TRANS_CTRL, "new udp channel failed.");
        return NULL;
    }

    if (memcpy_s(&(newChannel->info), sizeof(newChannel->info), info, sizeof(AppInfo)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s failed.");
        SoftBusFree(newChannel);
        return NULL;
    }
    if (CopyAppInfoFastTransData(newChannel, info) != SOFTBUS_OK) {
        (void)memset_s(newChannel->info.sessionKey, sizeof(newChannel->info.sessionKey), 0,
            sizeof(newChannel->info.sessionKey));
        SoftBusFree(newChannel);
        TRANS_LOGE(TRANS_CTRL, "copy appinfo fast trans data fail");
        return NULL;
    }
    return newChannel;
}

static int32_t AcceptUdpChannelAsServer(AppInfo *appInfo, AuthHandle *authHandle, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL, "process udp channel open state[as server].");
    int32_t udpChannelId = GenerateUdpChannelId();
    if (udpChannelId == INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "generate udp channel id failed.");
        return SOFTBUS_TRANS_UDP_INVALID_CHANNEL_ID;
    }
    appInfo->myData.channelId = udpChannelId;
    int32_t ret = LnnGetNetworkIdByUuid(
        (const char *)appInfo->peerData.deviceId, appInfo->peerNetWorkId, NETWORK_ID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get network id by uuid failed.");
    }
    UdpChannelInfo *newChannel = NewUdpChannelByAppInfo(appInfo);
    if (newChannel == NULL) {
        ReleaseUdpChannelId(appInfo->myData.channelId);
        return SOFTBUS_MEM_ERR;
    }
    newChannel->seq = seq;
    newChannel->status = UDP_CHANNEL_STATUS_INIT;
    if (memcpy_s(&(newChannel->authHandle), sizeof(AuthHandle), authHandle, sizeof(AuthHandle)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s authHandle failed.");
        return SOFTBUS_MEM_ERR;
    }
    if (TransAddUdpChannel(newChannel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add new udp channel failed.");
        ReleaseUdpChannelId(appInfo->myData.channelId);
        SoftBusFree(newChannel);
        return SOFTBUS_TRANS_UDP_SERVER_ADD_CHANNEL_FAILED;
    }

    ret = CheckCollabRelation(appInfo, udpChannelId, CHANNEL_TYPE_UDP);
    if (ret == SOFTBUS_TRANS_NOT_NEED_CHECK_RELATION) {
        ret = NotifyUdpChannelOpened(appInfo, true);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "Trans send on channel opened request fail. ret=%{public}d.", ret);
            return ret;
        }
        return SOFTBUS_OK;
    }

    return SOFTBUS_OK;
}

static int32_t AcceptUdpChannelAsClient(AppInfo *appInfo)
{
    TRANS_LOGI(TRANS_CTRL, "process udp channel open state[as client].");
    int32_t ret = NotifyUdpChannelOpened(appInfo, false);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify app udp channel opened failed.");
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t CloseUdpChannel(AppInfo *appInfo, bool isServerSide)
{
    TRANS_LOGI(TRANS_CTRL, "process udp channel close state");
    if (TransDelUdpChannel(appInfo->myData.channelId) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "delete udp channel failed.");
    }
    int32_t messageType = isServerSide ? MESSAGE_TYPE_NOMAL : MESSAGE_TYPE_CLOSE_ACK;
    if (NotifyUdpChannelClosed(appInfo, messageType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "notify app udp channel closed failed.");
    }
    return SOFTBUS_OK;
}

void NotifyWifiByAddScenario(StreamType streamType, int32_t pid)
{
    if (streamType == COMMON_AUDIO_STREAM || streamType == COMMON_VIDEO_STREAM) {
        if (AddScenario(LOCAL_MAC_1, PEER_MAC_1, pid, SM_AUDIO_TYPE) !=0) {
            TRANS_LOGE(TRANS_CTRL, "notify wifi scan failed!");
        } else {
            TRANS_LOGI(TRANS_CTRL, "notify wifi scan success!");
        }
    }
}

void NotifyWifiByDelScenario(StreamType streamType, int32_t pid)
{
    if (streamType == COMMON_AUDIO_STREAM || streamType == COMMON_VIDEO_STREAM) {
        if (DelScenario(LOCAL_MAC_1, PEER_MAC_1, pid, SM_AUDIO_TYPE) !=0) {
            TRANS_LOGE(TRANS_CTRL, "recover wifi scan failed");
        } else {
            TRANS_LOGI(TRANS_CTRL, "recover wifi scan success!");
        }
    }
}

static int32_t ProcessUdpChannelState(AppInfo *appInfo, bool isServerSide, AuthHandle *authHandle, int64_t seq)
{
    int32_t ret = SOFTBUS_OK;
    switch (appInfo->udpChannelOptType) {
        case TYPE_UDP_CHANNEL_OPEN:
            NotifyWifiByAddScenario(appInfo->streamType, appInfo->myData.pid);
            if (isServerSide) {
                ret = AcceptUdpChannelAsServer(appInfo, authHandle, seq);
            } else {
                ret = AcceptUdpChannelAsClient(appInfo);
            }
            return ret;
        case TYPE_UDP_CHANNEL_CLOSE:
            NotifyWifiByDelScenario(appInfo->streamType, appInfo->myData.pid);
            ret = CloseUdpChannel(appInfo, isServerSide);
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid udp channel type.");
            return SOFTBUS_TRANS_INVALID_CHANNEL_TYPE;
    }
    return SOFTBUS_OK;
}

static int32_t SendUdpInfo(cJSON *replyMsg, AuthHandle authHandle, int64_t seq)
{
    char *msgStr = cJSON_PrintUnformatted(replyMsg);
    if (msgStr == NULL) {
        return SOFTBUS_PARSE_JSON_ERR;
    }
    AuthTransData dataInfo = {
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REPLY,
        .seq = seq,
        .len = strlen(msgStr) + 1,
        .data = (const uint8_t *)msgStr,
    };

    int32_t ret = AuthPostTransData(authHandle, &dataInfo);
    cJSON_free(msgStr);
    return ret;
}

int32_t SendReplyErrInfo(int errCode, char* errDesc, AuthHandle authHandle, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL, "udp send reply info in.");
    cJSON *replyMsg = cJSON_CreateObject();
    TRANS_CHECK_AND_RETURN_RET_LOGE(replyMsg != NULL, SOFTBUS_CREATE_JSON_ERR,
        TRANS_CTRL, "create cjson object failed.");
    int32_t ret = TransPackReplyErrInfo(replyMsg, errCode, errDesc);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack request udp info failed.");
        cJSON_Delete(replyMsg);
        return ret;
    }
    ret = SendUdpInfo(replyMsg, authHandle, seq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SendReplyeErrInfo failed.");
        cJSON_Delete(replyMsg);
        return ret;
    }
    cJSON_Delete(replyMsg);
    TRANS_LOGE(TRANS_CTRL, "udp send reply error info out.");
    return SOFTBUS_OK;
}

static int32_t SendReplyUdpInfo(AppInfo *appInfo, AuthHandle authHandle, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL, "udp send reply info in.");
    cJSON *replyMsg = cJSON_CreateObject();
    TRANS_CHECK_AND_RETURN_RET_LOGE(replyMsg != NULL, SOFTBUS_CREATE_JSON_ERR,
        TRANS_CTRL, "create cjson object failed.");
    int32_t ret = TransPackReplyUdpInfo(replyMsg, appInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack request udp info failed.");
        cJSON_Delete(replyMsg);
        return ret;
    }
    ret = SendUdpInfo(replyMsg, authHandle, seq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "SendReplyeErrInfo failed.");
        cJSON_Delete(replyMsg);
        return ret;
    }

    cJSON_Delete(replyMsg);
    TRANS_LOGI(TRANS_CTRL, "udp send reply info out.");
    return SOFTBUS_OK;
}

static int32_t SetPeerDeviceIdByAuth(AuthHandle authHandle, AppInfo *appInfo)
{
    char peerUuid[UUID_BUF_LEN] = { 0 };
    int32_t ret = AuthGetDeviceUuid(authHandle.authId, peerUuid, sizeof(peerUuid));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get peer uuid by auth id failed, ret=%{public}d.", ret);
        return ret;
    }

    if (memcpy_s(appInfo->peerData.deviceId, sizeof(appInfo->peerData.deviceId),
        peerUuid, sizeof(peerUuid)) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "memcpy_s network id failed.");
        return SOFTBUS_MEM_ERR;
    }

    return SOFTBUS_OK;
}

static void TransSetUdpConnectTypeByAuthType(int32_t *connectType, AuthHandle authHandle)
{
    switch (authHandle.type) {
        case AUTH_LINK_TYPE_P2P:
            *connectType = CONNECT_P2P;
            break;
        case AUTH_LINK_TYPE_ENHANCED_P2P:
            *connectType = CONNECT_HML;
            break;
        case AUTH_LINK_TYPE_WIFI:
            *connectType = CONNECT_TCP;
            break;
        default:
            break;
    }
}

static int32_t ParseRequestAppInfo(AuthHandle authHandle, const cJSON *msg, AppInfo *appInfo)
{
    int32_t ret = TransUnpackRequestUdpInfo(msg, appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "unpack request udp info failed.");

    if (appInfo->callingTokenId != TOKENID_NOT_SET &&
        TransCheckServerAccessControl(appInfo->callingTokenId) != SOFTBUS_OK) {
        return SOFTBUS_TRANS_CHECK_ACL_FAILED;
    }
    if (CheckSecLevelPublic(appInfo->myData.sessionName, appInfo->peerData.sessionName) != SOFTBUS_OK) {
        return SOFTBUS_PERMISSION_SERVER_DENIED;
    }
    appInfo->myHandleId = -1;
    appInfo->peerHandleId = -1;
    ret = g_channelCb->GetPkgNameBySessionName(appInfo->myData.sessionName,
        appInfo->myData.pkgName, PKG_NAME_SIZE_MAX);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
        SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED, TRANS_CTRL, "get pkgName failed, ret=%{public}d", ret);

    ret = g_channelCb->GetUidAndPidBySessionName(appInfo->myData.sessionName, &appInfo->myData.uid,
        &appInfo->myData.pid);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK,
        SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED, TRANS_CTRL, "get uid and pid failed, ret=%{public}d", ret);

    if (appInfo->udpChannelOptType != TYPE_UDP_CHANNEL_OPEN) {
        return SOFTBUS_OK;
    }

    TransSetUdpConnectTypeByAuthType(&appInfo->connectType, authHandle);

    ret = SetPeerDeviceIdByAuth(authHandle, appInfo);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_PEER_PROC_ERR, TRANS_CTRL, "set deviceId failed.");

    char localIp[IP_LEN] = { 0 };
    if (appInfo->udpConnType == UDP_CONN_TYPE_WIFI) {
        appInfo->routeType = WIFI_STA;
        ret = LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, localIp, sizeof(localIp));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get local strInfo failed.");
    } else {
        appInfo->routeType = WIFI_P2P;
        struct WifiDirectManager *mgr = GetWifiDirectManager();
        TRANS_CHECK_AND_RETURN_RET_LOGE(mgr != NULL && mgr->getLocalIpByRemoteIp != NULL,
            SOFTBUS_WIFI_DIRECT_INIT_FAILED, TRANS_CTRL, "get mgr obj failed.");

        ret = mgr->getLocalIpByRemoteIp(appInfo->peerData.addr, localIp, sizeof(localIp));
        TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get localIp failed, ret=%{public}d", ret);
    }
    ret = strcpy_s(appInfo->myData.addr, sizeof(appInfo->myData.addr), localIp);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == EOK, SOFTBUS_STRCPY_ERR, TRANS_CTRL, "strcpy_s my ip addr failed.");

    return SOFTBUS_OK;
}

/**
 * don't care release resources when close status, after invoking process udp channel status.
 * */
static void ProcessAbnormalUdpChannelState(const AppInfo *info, int32_t errCode, bool needClose)
{
    if (errCode == SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED) {
        (void)TransAddTimestampToList(
            info->myData.sessionName, info->peerData.sessionName, info->peerNetWorkId, SoftBusGetSysTimeMs());
    }
    if (info->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
        (void)NotifyUdpChannelOpenFailed(info, errCode);
        (void)TransDelUdpChannel(info->myData.channelId);
    } else if (needClose) {
        NotifyUdpChannelClosed(info, MESSAGE_TYPE_NOMAL);
        (void)TransDelUdpChannel(info->myData.channelId);
    }
}

static void TransOnExchangeUdpInfoReply(AuthHandle authHandle, int64_t seq, const cJSON *msg)
{
    /* receive reply message */
    TRANS_LOGI(TRANS_CTRL, "receive reply udp negotiation info.");
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(channel), 0, sizeof(channel));

    if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_DONE, true) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set udp channel negotiation status done failed.");
        return;
    }
    if (TransGetUdpChannelBySeq(seq, &channel, true) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udp channel by seq failed.");
        return;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(channel.info.myData.channelId + ID_OFFSET));
    int32_t errCode = SOFTBUS_OK;
    if (TransUnpackReplyErrInfo(msg, &errCode) == SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "receive err reply info, channelId=%{public}" PRId64, channel.info.myData.channelId);
        ProcessAbnormalUdpChannelState(&(channel.info), errCode, true);
        return;
    }
    int32_t ret = TransUnpackReplyUdpInfo(msg, &(channel.info));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "unpack reply udp info fail channelId=%{public}" PRId64, channel.info.myData.channelId);
        ProcessAbnormalUdpChannelState(&(channel.info), ret, true);
        return;
    }
    TransUpdateUdpChannelInfo(seq, &(channel.info), true);
    ret = ProcessUdpChannelState(&(channel.info), false, &authHandle, seq);
    (void)memset_s(channel.info.sessionKey, sizeof(channel.info.sessionKey), 0, sizeof(channel.info.sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL,
            "process udp channelId=%{public}" PRId64 " failed, close peer", channel.info.myData.channelId);
        (void)TransCloseUdpChannel(channel.info.myData.channelId);
        ProcessAbnormalUdpChannelState(&(channel.info), ret, false);
        return;
    }
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = channel.info.myData.channelId,
        .authId = authHandle.authId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_REPLY, extra);
}

static void ReportUdpRequestHandShakeStartEvent(
    const AppInfo *info, NodeInfo *nodeInfo, TransEventExtra *extra, int64_t authId)
{
    extra->channelType = CHANNEL_TYPE_UDP;
    extra->authId = authId;
    if (info->udpChannelOptType != TYPE_UDP_CHANNEL_OPEN) {
        return;
    }

    if (LnnGetRemoteNodeInfoById(info->peerData.deviceId, CATEGORY_UUID, nodeInfo) == SOFTBUS_OK) {
        extra->peerUdid = nodeInfo->deviceInfo.deviceUdid;
        extra->peerDevVer = nodeInfo->deviceInfo.deviceVersion;
    }
    if (LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, nodeInfo->masterUdid, UDID_BUF_LEN) == SOFTBUS_OK) {
        extra->localUdid = nodeInfo->masterUdid;
    }
    extra->socketName = info->myData.sessionName;
    extra->peerChannelId = info->peerData.channelId;
    extra->result = EVENT_STAGE_RESULT_OK;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_START, *extra);
}

static void ReportUdpRequestHandShakeReplyEvent(
    const AppInfo *info, TransEventExtra *extra, int32_t result, int32_t errCode)
{
    if (extra->socketName != NULL && info->udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
        extra->result = result;
        extra->errcode = errCode;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_HANDSHAKE_REPLY, *extra);
    }
}

static void TransOnExchangeUdpInfoRequest(AuthHandle authHandle, int64_t seq, const cJSON *msg)
{
    /* receive request message */
    TRANS_LOGI(TRANS_CTRL, "receive request udp negotiation info.");
    AppInfo info;
    (void)memset_s(&info, sizeof(info), 0, sizeof(info));
    info.myData.channelId = INVALID_CHANNEL_ID;
    char *errDesc = NULL;

    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t ret = ParseRequestAppInfo(authHandle, msg, &info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get appinfo failed. ret=%{public}d", ret);
        errDesc = (char *)"peer device session name not create";
        goto ERR_EXIT;
    }

    ReportUdpRequestHandShakeStartEvent(&info, &nodeInfo, &extra, authHandle.authId);
    ret = ProcessUdpChannelState(&info, true, &authHandle, seq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "process udp channel state failed. ret=%{public}d", ret);
        errDesc = (char *)"notify app error";
        ProcessAbnormalUdpChannelState(&info, ret, false);
        goto ERR_EXIT;
    }

    if (info.udpChannelOptType == TYPE_UDP_CHANNEL_CLOSE) {
        ret = SendReplyUdpInfo(&info, authHandle, seq);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "send reply udp info failed. ret=%{public}d.", ret);
            errDesc = (char *)"send reply error";
            ProcessAbnormalUdpChannelState(&info, ret, false);
            goto ERR_EXIT;
        }
        ReportUdpRequestHandShakeReplyEvent(&info, &extra, EVENT_STAGE_RESULT_OK, SOFTBUS_OK);
    }
    return;
ERR_EXIT:
    ReportUdpRequestHandShakeReplyEvent(&info, &extra, EVENT_STAGE_RESULT_FAILED, ret);
    if (SendReplyErrInfo(ret, errDesc, authHandle, seq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reply error info failed.");
    }
}

static void TransOnExchangeUdpInfo(AuthHandle authHandle, int32_t isReply, int64_t seq, const cJSON *msg)
{
    if (isReply) {
        TransOnExchangeUdpInfoReply(authHandle, seq, msg);
    } else {
        TransOnExchangeUdpInfoRequest(authHandle, seq, msg);
    }
}

static int32_t StartExchangeUdpInfo(UdpChannelInfo *channel, AuthHandle authHandle, int64_t seq)
{
    TRANS_LOGI(TRANS_CTRL,
        "start exchange udp info: channelId=%{public}" PRId64 ", authId=%{public}" PRId64 ", streamType=%{public}d",
        channel->info.myData.channelId, authHandle.authId, channel->info.streamType);
    cJSON *requestMsg = cJSON_CreateObject();
    if (requestMsg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create cjson object failed.");
        return SOFTBUS_MEM_ERR;
    }

    if (TransPackRequestUdpInfo(requestMsg, &(channel->info)) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "pack request udp info failed.");
        cJSON_Delete(requestMsg);
        return SOFTBUS_TRANS_UDP_PACK_INFO_FAILED;
    }
    char *msgStr = cJSON_PrintUnformatted(requestMsg);
    cJSON_Delete(requestMsg);
    if (msgStr == NULL) {
        TRANS_LOGE(TRANS_CTRL, "cjson unformatted failed.");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    AuthTransData dataInfo = {
        .module = MODULE_UDP_INFO,
        .flag = FLAG_REQUEST,
        .seq = seq,
        .len = strlen(msgStr) + 1,
        .data = (const uint8_t *)msgStr,
    };
    int32_t ret = SOFTBUS_AUTH_REG_DATA_FAIL;
    ret = AuthPostTransData(authHandle, &dataInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "AuthPostTransData failed.");
        cJSON_free(msgStr);
        return ret;
    }
    cJSON_free(msgStr);
    if (TransSetUdpChannelStatus(seq, UDP_CHANNEL_STATUS_NEGING, true) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set udp channel negotiation status neging failed.");
    }
    TransEventExtra extra = {
        .socketName = NULL,
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .channelId = (int32_t)channel->info.myData.channelId,
        .authId = (int32_t)authHandle.authId,
        .result = EVENT_STAGE_RESULT_OK
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    return SOFTBUS_OK;
}

static void ClientFillTransEventExtra(uint32_t requestId, AuthHandle authHandle, TransEventExtra *extra)
{
    extra->socketName = NULL;
    extra->peerNetworkId = NULL;
    extra->calleePkg = NULL;
    extra->callerPkg = NULL;
    extra->requestId = (int32_t)requestId;
    extra->authId = (int32_t)authHandle.authId;
    extra->result = EVENT_STAGE_RESULT_OK;
}

static void UdpOnAuthConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    TransEventExtra extra = {0};
    ClientFillTransEventExtra(requestId, authHandle, &extra);
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    TRANS_LOGI(
        TRANS_CTRL, "reqId=%{public}u, authId=%{public}" PRId64, requestId, authHandle.authId);
    int32_t ret = SOFTBUS_MALLOC_ERR;
    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (channel == NULL) {
        ret = SOFTBUS_MALLOC_ERR;
        goto EXIT_ERR;
    }
    if (TransGetUdpChannelByRequestId(requestId, channel) != SOFTBUS_OK) {
        ret = SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
        TRANS_LOGE(TRANS_CTRL, "get channel fail");
        goto EXIT_ERR;
    }
    TransSetUdpChannelMsgType(requestId);
    extra.channelId = (int32_t)channel->info.myData.channelId;
    ret = StartExchangeUdpInfo(channel, authHandle, channel->seq);
    (void)memset_s(channel->info.sessionKey, sizeof(channel->info.sessionKey), 0,
        sizeof(channel->info.sessionKey));
    if (ret != SOFTBUS_OK) {
        channel->errCode = ret;
        TRANS_LOGE(TRANS_CTRL, "neg fail");
        ProcessAbnormalUdpChannelState(&channel->info, SOFTBUS_TRANS_HANDSHAKE_ERROR, true);
        extra.socketName = channel->info.myData.sessionName;
        extra.channelId = channel->info.myData.channelId;
        goto EXIT_ERR;
    }

    SoftBusFree(channel);
    TRANS_LOGD(TRANS_CTRL, "ok");
    return;
EXIT_ERR:
    extra.channelType = CHANNEL_TYPE_UDP;
    extra.requestId = (int32_t)requestId;
    extra.authId = authHandle.authId;
    extra.errcode = ret;
    extra.result = EVENT_STAGE_RESULT_FAILED;
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_HANDSHAKE_START, extra);
    SoftBusFree(channel);
    TRANS_LOGE(TRANS_CTRL, "proc fail");
    AuthCloseConn(authHandle);
}

static void UdpOnAuthConnOpenFailed(uint32_t requestId, int32_t reason)
{
    TRANS_LOGW(TRANS_CTRL, "reqId=%{public}u, reason=%{public}d", requestId, reason);
    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (channel == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail");
        return;
    }
    int32_t ret = TransGetUdpChannelByRequestId(requestId, channel);
    (void)memset_s(channel->info.sessionKey, sizeof(channel->info.sessionKey), 0,
        sizeof(channel->info.sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "UdpOnAuthConnOpened get channel fail");
        SoftBusFree(channel);
        return;
    }
    ProcessAbnormalUdpChannelState(&channel->info, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED, true);
    TransEventExtra extra = {
        .peerNetworkId = NULL,
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = channel->info.myData.sessionName,
        .channelType = CHANNEL_TYPE_UDP,
        .channelId = channel->info.myData.channelId,
        .requestId = requestId,
        .errcode = reason,
        .result = EVENT_STAGE_RESULT_FAILED
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    SoftBusFree(channel);
    TRANS_LOGW(TRANS_CTRL, "ok");
}

static void TransCloseUdpChannelByRequestId(uint32_t requestId)
{
    TRANS_LOGD(TRANS_CTRL, "reqId=%{public}u", requestId);
    UdpChannelInfo *channel = (UdpChannelInfo *)SoftBusCalloc(sizeof(UdpChannelInfo));
    if (channel == NULL) {
        TRANS_LOGE(TRANS_CTRL, "malloc fail");
        return;
    }
    if (TransGetUdpChannelByRequestId(requestId, channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channel fail");
        SoftBusFree(channel);
        return;
    }
    (void)memset_s(channel->info.sessionKey, sizeof(channel->info.sessionKey), 0,
        sizeof(channel->info.sessionKey));
    ProcessAbnormalUdpChannelState(&channel->info, SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED, true);
    SoftBusFree(channel);
    TRANS_LOGD(TRANS_CTRL, "ok");
}

static int32_t CheckAuthConnStatus(const uint32_t requestId)
{
    UdpChannelInfo channel;
    if (TransGetUdpChannelByRequestId(requestId, &channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get channel fail");
        return SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED;
    }
    (void)memset_s(channel.info.sessionKey, sizeof(channel.info.sessionKey), 0, sizeof(channel.info.sessionKey));
    return channel.errCode;
}

static int32_t UdpOpenAuthConn(const char *peerUdid, uint32_t requestId, bool isMeta, int32_t linkType)
{
    AuthConnInfo auth;
    (void)memset_s(&auth, sizeof(AuthConnInfo), 0, sizeof(AuthConnInfo));
    AuthConnCallback cb = {0};
    int32_t ret = SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED;
    if (linkType == LANE_HML || linkType == LANE_P2P_REUSE) {
        TRANS_LOGI(TRANS_CTRL, "get AuthConnInfo, linkType=%{public}d", linkType);
        ret = AuthGetHmlConnInfo(peerUdid, &auth, isMeta);
    }
    if (ret != SOFTBUS_OK && (linkType == LANE_P2P || linkType == LANE_P2P_REUSE)) {
        TRANS_LOGI(TRANS_CTRL, "get AuthConnInfo, linkType=%{public}d", linkType);
        ret = AuthGetP2pConnInfo(peerUdid, &auth, isMeta);
    }
    if (ret != SOFTBUS_OK) {
        ret = AuthGetPreferConnInfo(peerUdid, &auth, isMeta);
    }
    if (ret != SOFTBUS_OK) {
        ret = AuthGetPreferConnInfo(peerUdid, &auth, true);
        isMeta = true;
    }
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get info fail: ret=%{public}d", ret);
        TransCloseUdpChannelByRequestId(requestId);
        return ret;
    }

    cb.onConnOpened = UdpOnAuthConnOpened;
    cb.onConnOpenFailed = UdpOnAuthConnOpenFailed;
    ret = AuthOpenConn(&auth, requestId, &cb, isMeta);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "open fail: ret=%{public}d", ret);
        TransCloseUdpChannelByRequestId(requestId);
        return ret;
    }
    ret = CheckAuthConnStatus(requestId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "status check failed: ret=%{public}d", ret);
        TransCloseUdpChannelByRequestId(requestId);
        return ret;
    }

    TRANS_LOGI(TRANS_CTRL, "ok: reqId=%{public}u", requestId);
    return SOFTBUS_OK;
}

static bool TransUdpGetAuthType(const char *peerNetWorkId, const char *mySessionName)
{
    if (!CompareSessionName(CLONE_SESSION_NAME, mySessionName) &&
        CompareSessionName(ISHARE_SESSION_NAME, mySessionName) &&
        IsAvailableMeta(peerNetWorkId)) {
        return true;
    }
    return TransGetAuthTypeByNetWorkId(peerNetWorkId);
}

static int32_t OpenAuthConnForUdpNegotiation(UdpChannelInfo *channel)
{
    TRANS_LOGD(TRANS_CTRL, "enter.");
    if (channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t requestId = AuthGenRequestId();

    if (GetUdpChannelLock() != SOFTBUS_OK) {
        return SOFTBUS_LOCK_ERR;
    }
    UdpChannelInfo *channelObj = TransGetChannelObj(channel->info.myData.channelId);
    if (channelObj == NULL) {
        ReleaseUdpChannelLock();
        return SOFTBUS_NOT_FIND;
    }
    channelObj->requestId = requestId;
    channelObj->status = UDP_CHANNEL_STATUS_OPEN_AUTH;
    bool isMeta = TransUdpGetAuthType(channel->info.peerNetWorkId, channel->info.myData.sessionName);
    ReleaseUdpChannelLock();

    TransEventExtra extra = {
        .calleePkg = NULL,
        .callerPkg = NULL,
        .socketName = channel->info.myData.sessionName,
        .channelType = CHANNEL_TYPE_UDP,
        .channelId = channel->info.myData.channelId,
        .requestId = requestId,
        .peerNetworkId = channel->info.peerNetWorkId
    };
    TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
    int32_t ret = UdpOpenAuthConn(channel->info.peerData.deviceId, requestId, isMeta, channel->info.linkType);
    if (ret != SOFTBUS_OK) {
        extra.errcode = ret;
        extra.result = EVENT_STAGE_RESULT_FAILED;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_START_CONNECT, extra);
        TRANS_LOGE(TRANS_CTRL, "open auth conn fail");
        return SOFTBUS_TRANS_OPEN_AUTH_CHANNEL_FAILED;
    }
    TRANS_LOGD(TRANS_CTRL, "ok");
    return SOFTBUS_OK;
}

static int32_t PrepareAppInfoForUdpOpen(const ConnectOption *connOpt, AppInfo *appInfo, int32_t *channelId)
{
    appInfo->peerData.port = connOpt->socketOption.port;
    if (strcpy_s(appInfo->peerData.addr, sizeof(appInfo->peerData.addr), connOpt->socketOption.addr) != EOK) {
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = SoftBusGenerateSessionKey(appInfo->sessionKey, sizeof(appInfo->sessionKey));
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "generate session key failed.");

    int32_t connType = connOpt->type;
    switch (connType) {
        case CONNECT_TCP:
            appInfo->udpConnType = UDP_CONN_TYPE_WIFI;
            appInfo->routeType = WIFI_STA;
            ret = LnnGetLocalStrInfo(STRING_KEY_WLAN_IP, appInfo->myData.addr, sizeof(appInfo->myData.addr));
            TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "get local ip fail");
            appInfo->protocol = connOpt->socketOption.protocol;
            break;
        case CONNECT_P2P:
        case CONNECT_P2P_REUSE:
        case CONNECT_HML:
            appInfo->udpConnType = UDP_CONN_TYPE_P2P;
            appInfo->routeType = WIFI_P2P;
            appInfo->protocol = connOpt->socketOption.protocol;
            break;
        default:
            TRANS_LOGE(TRANS_CTRL, "invalid connType.");
            return SOFTBUS_CONN_INVALID_CONN_TYPE;
    }

    int32_t id = GenerateUdpChannelId();
    if (id == INVALID_ID) {
        TRANS_LOGE(TRANS_CTRL, "generate udp channel id failed.");
        return SOFTBUS_TRANS_UDP_INVALID_CHANNEL_ID;
    }
    *channelId = id;
    appInfo->myData.channelId = id;
    appInfo->udpChannelOptType = TYPE_UDP_CHANNEL_OPEN;
    return SOFTBUS_OK;
}

static int32_t TransUdpGetChannelAndOpenConn(int32_t channelId)
{
    UdpChannelInfo udpChannel;
    (void)memset_s(&udpChannel, sizeof(udpChannel), 0, sizeof(udpChannel));
    int32_t ret = TransGetUdpChannelById(channelId, &udpChannel);
    (void)memset_s(udpChannel.info.sessionKey, sizeof(udpChannel.info.sessionKey), 0,
        sizeof(udpChannel.info.sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udp channel by channel id failed. channelId=%{public}d", channelId);
        ReleaseUdpChannelId(channelId);
        return ret;
    }
    ret = OpenAuthConnForUdpNegotiation(&udpChannel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "open udp negotiation failed. channelId=%{public}d", channelId);
        ReleaseUdpChannelId(channelId);
        TransDelUdpChannel(channelId);
        return ret;
    }
    return SOFTBUS_OK;
}

int32_t TransOpenUdpChannel(AppInfo *appInfo, const ConnectOption *connOpt, int32_t *channelId)
{
    TRANS_LOGI(TRANS_CTRL, "server trans open udp channel.");
    if (appInfo == NULL || connOpt == NULL || channelId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invaild param.");
        return SOFTBUS_INVALID_PARAM;
    }
    int32_t id;
    if (PrepareAppInfoForUdpOpen(connOpt, appInfo, &id) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "prepare app info for opening udp channel.");
        return SOFTBUS_TRANS_UDP_PREPARE_APP_INFO_FAILED;
    }
    SoftbusHitraceStart(SOFTBUS_HITRACE_ID_VALID, (uint64_t)(id + ID_OFFSET));
    TRANS_LOGI(TRANS_CTRL,
        "SoftbusHitraceChainBegin: set HitraceId=%{public}" PRIu64, (uint64_t)(id + ID_OFFSET));
    UdpChannelInfo *newChannel = NewUdpChannelByAppInfo(appInfo);
    if (newChannel == NULL) {
        TRANS_LOGE(TRANS_CTRL, "new udp channel failed.");
        ReleaseUdpChannelId(id);
        return SOFTBUS_MEM_ERR;
    }
    newChannel->seq = GenerateSeq(false);
    newChannel->status = UDP_CHANNEL_STATUS_INIT;
    int32_t ret = TransAddUdpChannel(newChannel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add new udp channel failed.");
        ReleaseUdpChannelId(id);
        if (newChannel->info.fastTransData != NULL) {
            SoftBusFree((void *)newChannel->info.fastTransData);
        }
        (void)memset_s(newChannel->info.sessionKey, sizeof(newChannel->info.sessionKey), 0,
            sizeof(newChannel->info.sessionKey));
        SoftBusFree(newChannel);
        return ret;
    }

    ret = TransUdpGetChannelAndOpenConn(id);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "set udp channel by channel id failed. channelId=%{public}d", id);
        return ret;
    }
    *channelId = id;
    return SOFTBUS_OK;
}

int32_t TransCloseUdpChannel(int32_t channelId)
{
    TRANS_LOGI(TRANS_CTRL, "server trans close udp channel.");
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(channel), 0, sizeof(channel));

    int32_t ret = TransSetUdpChannelOptType(channelId, TYPE_UDP_CHANNEL_CLOSE);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "set udp channel close type failed.");

    ret = TransGetUdpChannelById(channelId, &channel);
    (void)memset_s(channel.info.sessionKey, sizeof(channel.info.sessionKey), 0, sizeof(channel.info.sessionKey));
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udp channel by channel id failed. channelId=%{public}d", channelId);
        return ret;
    }
    NotifyWifiByDelScenario(channel.info.streamType, channel.info.myData.pid);
    ret = OpenAuthConnForUdpNegotiation(&channel);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "open udp negotiation failed.");

    return SOFTBUS_OK;
}

static void UdpModuleCb(AuthHandle authHandle, const AuthTransData *data)
{
    if (data == NULL || data->data == NULL || data->len < 1) {
        TRANS_LOGW(TRANS_CTRL, "invalid param.");
        return;
    }
    if (authHandle.type < AUTH_LINK_TYPE_WIFI || authHandle.type >= AUTH_LINK_TYPE_MAX) {
        TRANS_LOGW(TRANS_CTRL, "authHandle type error");
        return;
    }
    TRANS_LOGI(TRANS_CTRL,
        "udp module callback enter: module=%{public}d, seq=%{public}" PRId64 ", len=%{public}u.",
        data->module, data->seq, data->len);
    cJSON *json = cJSON_ParseWithLength((char *)data->data, data->len);
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "cjson parse failed!");
        return;
    }
    TransOnExchangeUdpInfo(authHandle, data->flag, data->seq, json);
    cJSON_Delete(json);

    if (data->flag) {
        AuthCloseConn(authHandle);
    }
}

void TransUdpNodeOffLineProc(const LnnEventBasicInfo *info)
{
    if ((info == NULL) || (info->event != LNN_EVENT_NODE_ONLINE_STATE_CHANGED)) {
        return;
    }

    LnnOnlineStateEventInfo *onlineStateInfo = (LnnOnlineStateEventInfo*)info;
    if (onlineStateInfo->isOnline == true) {
        return;
    }

    TransCloseUdpChannelByNetWorkId(onlineStateInfo->networkId);
}

int32_t TransUdpChannelInit(IServerChannelCallBack *callback)
{
    g_channelCb = callback;
    int32_t ret = SoftBusMutexInit(&g_udpNegLock, NULL);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, SOFTBUS_TRANS_INIT_FAILED,
        TRANS_INIT, "g_udpNegLock init failed.");

    ret = TransUdpChannelMgrInit();
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "trans udp channel manager init failed.");
        (void)SoftBusMutexDestroy(&g_udpNegLock);
        return ret;
    }

    AuthTransListener transUdpCb = {
        .onDataReceived = UdpModuleCb,
        .onDisconnected = NULL,
        .onException = NULL,
    };

    ret = RegAuthTransListener(MODULE_UDP_INFO, &transUdpCb);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "register udp callback to auth failed.");
        (void)SoftBusMutexDestroy(&g_udpNegLock);
        return ret;
    }

    TRANS_LOGI(TRANS_INIT, "server trans udp channel init success.");
    return SOFTBUS_OK;
}

void TransUdpChannelDeinit(void)
{
    TransUdpChannelMgrDeinit();
    UnregAuthTransListener(MODULE_UDP_INFO);

    g_channelCb = NULL;
    TRANS_LOGI(TRANS_INIT, "server trans udp channel deinit success.");
}

void TransUdpDeathCallback(const char *pkgName, int32_t pid)
{
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "param invalid");
        return;
    }

    if (GetUdpChannelLock() != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "lock failed");
        return;
    }
    ListNode destroyList;
    ListInit(&destroyList);

    SoftBusList *udpChannelList = GetUdpChannelMgrHead();
    UdpChannelInfo *udpChannelNode = NULL;
    LIST_FOR_EACH_ENTRY(udpChannelNode, &(udpChannelList->list), UdpChannelInfo, node) {
        if ((strcmp(udpChannelNode->info.myData.pkgName, pkgName) == 0) && (udpChannelNode->info.myData.pid == pid)) {
            udpChannelNode->info.udpChannelOptType = TYPE_UDP_CHANNEL_CLOSE;
            UdpChannelInfo *tempNode = (UdpChannelInfo*)SoftBusMalloc(sizeof(UdpChannelInfo));
            if (tempNode == NULL) {
                continue;
            }
            *tempNode = *udpChannelNode;
            ListAdd(&destroyList, &tempNode->node);
            char *anonymizePkgName = NULL;
            Anonymize(pkgName, &anonymizePkgName);
            TRANS_LOGW(TRANS_CTRL, "add pkgName=%{public}s, pid=%{public}d", AnonymizeWrapper(anonymizePkgName), pid);
            AnonymizeFree(anonymizePkgName);
        }
    }
    (void)ReleaseUdpChannelLock();

    UdpChannelInfo *udpChannelNodeNext = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(udpChannelNode, udpChannelNodeNext, (&destroyList), UdpChannelInfo, node) {
        if (OpenAuthConnForUdpNegotiation(udpChannelNode) != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "open udp negotiation failed.");
        }
        NotifyWifiByDelScenario(udpChannelNode->info.streamType, pid);
        ListDelete(&udpChannelNode->node);
        SoftBusFree(udpChannelNode);
    }
    return;
}

static void TransProcessAsyncOpenUdpChannelFailed(
    UdpChannelInfo *channel, int32_t channelId, int32_t openResult, char* errDesc)
{
    TRANS_LOGE(TRANS_CTRL, "Open udp channel failed, channelId=%{public}d", channelId);
    errDesc = (char *)"open udp channel failed";
    ProcessAbnormalUdpChannelState(&channel->info, openResult, false);
    if (SendReplyErrInfo(openResult, errDesc, channel->authHandle, channel->seq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "open udp channel failed.");
    }
}

int32_t TransDealUdpChannelOpenResult(int32_t channelId, int32_t openResult, int32_t udpPort)
{
    int32_t ret = TransUdpUpdateUdpPort(channelId, udpPort);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udpPort failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    UdpChannelInfo channel;
    (void)memset_s(&channel, sizeof(UdpChannelInfo), 0, sizeof(UdpChannelInfo));
    ret = TransGetUdpChannelById(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udpChannel failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    ret = TransUdpUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "update count failed, channelId=%{public}d, ret=%{public}d", channelId, ret);
        return ret;
    }
    char *errDesc = NULL;
    if (openResult != SOFTBUS_OK) {
        TransProcessAsyncOpenUdpChannelFailed(&channel, channelId, openResult, errDesc);
        return SOFTBUS_OK;
    }
    TransEventExtra extra;
    (void)memset_s(&extra, sizeof(TransEventExtra), 0, sizeof(TransEventExtra));
    ret = SendReplyUdpInfo(&channel.info, channel.authHandle, channel.seq);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reply udp info failed. ret=%{public}d.", ret);
        errDesc = (char *)"send reply udp info error";
        goto ERR_EXIT;
    }
    if (channel.info.udpChannelOptType == TYPE_UDP_CHANNEL_OPEN) {
        ret = NotifyUdpChannelBind(&channel.info);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "notify bind fail ret=%{public}d, channelId=%{public}d", ret, channelId);
            errDesc = (char *)"notify OnBind failed";
            goto ERR_EXIT;
        }
    }
    ReportUdpRequestHandShakeReplyEvent(&channel.info, &extra, EVENT_STAGE_RESULT_OK, SOFTBUS_OK);
    return ret;
ERR_EXIT:
    ProcessAbnormalUdpChannelState(&channel.info, ret, false);
    ReportUdpRequestHandShakeReplyEvent(&channel.info, &extra, EVENT_STAGE_RESULT_FAILED, ret);
    if (SendReplyErrInfo(ret, errDesc, channel.authHandle, channel.seq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reply error info failed.");
    }
    return ret;
}

int32_t TransDealUdpCheckCollabResult(int32_t channelId, int32_t checkResult)
{
    char *errDesc = NULL;
    UdpChannelInfo channel = { 0 };
    int32_t ret = TransGetUdpChannelById(channelId, &channel);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get udp channel failed, channelId=%{public}d", channelId);
        return ret;
    }
    ret = TransUdpUpdateReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", channelId);
        errDesc = (char *)"TransUdpUpdateReplyCnt failed";
        goto ERR_EXIT;
    }
    // Remove old check tasks.
    TransCheckChannelOpenRemoveFromLooper(channelId);
    if (checkResult != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "disconnect device channelId=%{public}d", channelId);
        ret = checkResult;
        errDesc = (char *)"check Collab failed";
        goto ERR_EXIT;
    }
    // Reset the check count to 0.
    ret = TransUdpResetReplyCnt(channelId);
    if (ret != SOFTBUS_OK) {
        errDesc = (char *)"TransUdpResetReplyCnt failed";
        goto ERR_EXIT;
    }

    ret = NotifyUdpChannelOpened(&channel.info, true);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "Trans on channel opened failed ret=%{public}d", ret);
        errDesc = (char *)"NotifyUdpChannelOpened failed";
        goto ERR_EXIT;
    }
    return SOFTBUS_OK;

ERR_EXIT:
    (void)TransDelUdpChannel(channelId);
    if (SendReplyErrInfo(ret, errDesc, channel.authHandle, channel.seq) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "send reply error info failed.");
    }
    return ret;
}
