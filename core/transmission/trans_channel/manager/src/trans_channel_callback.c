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

#include "trans_channel_callback.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "securec.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "softbus_adapter_mem.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_error_code.h"
#include "legacy/softbus_hisysevt_transreporter.h"
#include "softbus_qos.h"
#include "trans_channel_common.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "trans_tcp_direct_sessionconn.h"
#include "trans_udp_channel_manager.h"

static IServerChannelCallBack g_channelCallBack;

static int32_t TransAddTcpChannel(const ChannelInfo *channel, const char *pkgName, int32_t pid)
{
    TcpChannelInfo *info = CreateTcpChannelInfo(channel);
    if (info == NULL) {
        TRANS_LOGE(TRANS_CTRL, "create new TcpChannelInfo failed.");
        return SOFTBUS_MEM_ERR;
    }
    info->pid = pid;
    if (strcpy_s(info->pkgName, sizeof(info->pkgName), pkgName) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "copy pkgName failed.");
        SoftBusFree(info);
        return SOFTBUS_STRCPY_ERR;
    }
    int32_t ret = TransAddTcpChannelInfo(info);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "TransAddTcpChannelInfo failed.");
        SoftBusFree(info);
    }
    return ret;
}

static int32_t TransServerOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    if (pkgName == NULL || sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[DEVICE_ID_SIZE_MAX] = { 0 };
    if (channel->isEncrypt) {
        GetRemoteUdidWithNetworkId(channel->peerDeviceId, peerUdid, sizeof(peerUdid));
    }
    int32_t osType = 0;
    GetOsTypeByNetworkId(channel->peerDeviceId, &osType);
    char localUdid[UDID_BUF_LEN] = { 0 };
    (void)LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, localUdid, sizeof(localUdid));
    char deviceVersion[DEVICE_VERSION_SIZE_MAX] = { 0 };
    TransGetRemoteDeviceVersion(channel->peerDeviceId, channel->isEncrypt ? CATEGORY_NETWORK_ID : CATEGORY_UDID,
        deviceVersion, sizeof(deviceVersion));
    int64_t timeStart = channel->timeStart;
    int64_t timediff = GetSoftbusRecordTimeMillis() - timeStart;
    TransEventExtra extra = {
        .calleePkg = NULL,
        .peerNetworkId = channel->peerDeviceId,
        .linkType = channel->connectType,
        .channelId = channel->channelId,
        .costTime = (int32_t)timediff,
        .result = EVENT_STAGE_RESULT_OK,
        .callerPkg = pkgName,
        .socketName = sessionName,
        .osType = (osType < 0) ? UNKNOW_OS_TYPE : osType,
        .peerDevVer = deviceVersion,
        .localUdid = localUdid,
        .peerUdid = channel->isEncrypt ? peerUdid : channel->peerDeviceId
    };
    extra.deviceState = TransGetDeviceState(channel->peerDeviceId);
    if (!channel->isServer) {
        CoreSessionState state = CORE_SESSION_STATE_INIT;
        TransGetSocketChannelStateByChannel(channel->channelId, channel->channelType, &state);
        if (state == CORE_SESSION_STATE_CANCELLING) {
            char *tmpName = NULL;
            Anonymize(sessionName, &tmpName);
            TRANS_LOGW(TRANS_CTRL, "Cancel bind name=%{public}s, channelId=%{public}d",
                AnonymizeWrapper(tmpName), channel->channelId);
            AnonymizeFree(tmpName);
            extra.result = EVENT_STAGE_RESULT_CANCELED;
            TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
            return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL;
        }
        TransSetSocketChannelStateByChannel(
            channel->channelId, channel->channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    }
    int32_t ret = !channel->isServer && channel->channelType == CHANNEL_TYPE_UDP && NotifyQosChannelOpened(channel);
    TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "NotifyQosChannelOpened failed.");
    int32_t sceneCommand = channel->isServer ? EVENT_SCENE_OPEN_CHANNEL_SERVER : EVENT_SCENE_OPEN_CHANNEL;
    TRANS_EVENT(sceneCommand, EVENT_STAGE_OPEN_CHANNEL_END, extra);

    SoftbusRecordOpenSessionKpi(pkgName, channel->linkType, SOFTBUS_EVT_OPEN_SESSION_SUCC, timediff);
    SoftbusHitraceStop();
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT) {
        (void)TransAddTcpChannel(channel, pkgName, pid);
    }
    ret = ClientIpcOnChannelOpened(pkgName, sessionName, channel, pid);
    if (channel->channelType == CHANNEL_TYPE_TCP_DIRECT && ret != SOFTBUS_OK) {
        (void)TransDelTcpChannelInfoByChannelId(channel->channelId);
    }
    if (!IsTdcRecoveryTransLimit() || !IsUdpRecoveryTransLimit()) {
        (void)UdpChannelFileTransLimit(channel, FILE_PRIORITY_BK);
    }
    return ret;
}

static int32_t TransServerOnChannelClosed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t messageType)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    (void)TransLaneMgrDelLane(channelId, channelType, true);
    NotifyQosChannelClosed(channelId, channelType);
    ChannelMsg data = {
        .msgChannelId = channelId,
        .msgChannelType = channelType,
        .msgPid = pid,
        .msgMessageType = messageType,
        .msgPkgName = pkgName,
        .msgUuid = NULL,
        .msgUdid = NULL
    };
    TransDeleteSocketChannelInfoByChannel(channelId, channelType);
    if (ClientIpcOnChannelClosed(&data) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel close fail");
        return SOFTBUS_IPC_ERR;
    }
    if (IsTdcRecoveryTransLimit() && IsUdpRecoveryTransLimit()) {
        UdpChannelFileTransRecoveryLimit(FILE_PRIORITY_BE);
    }
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (TransLaneMgrDelLane(channelId, channelType, true) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_CTRL, "delete lane object failed.");
    }
    NotifyQosChannelClosed(channelId, channelType);
    ChannelMsg data = {
        .msgChannelId = channelId,
        .msgChannelType = channelType,
        .msgPid = pid,
        .msgPkgName = pkgName,
        .msgUuid = NULL,
        .msgUdid = NULL
    };
    TransDeleteSocketChannelInfoByChannel(channelId, channelType);
    if (ClientIpcOnChannelOpenFailed(&data, errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel open fail");
        return SOFTBUS_IPC_ERR;
    }
    SoftbusHitraceStop();
    TRANS_LOGW(TRANS_CTRL,
        "trasn server on channel open failed. pkgname=%{public}s, channelId=%{public}d, type=%{public}d",
        pkgName, channelId, channelType);
    return SOFTBUS_OK;
}

static int32_t TransServerOnMsgReceived(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType,
    TransReceiveData* receiveData)
{
    if (pkgName == NULL || receiveData == NULL || receiveData->data == NULL || receiveData->dataLen == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    ChannelMsg data = {
        .msgChannelId = channelId,
        .msgChannelType = channelType,
        .msgPid = pid,
        .msgPkgName = pkgName,
        .msgUuid = NULL,
        .msgUdid = NULL
    };
    if (ClientIpcOnChannelMsgReceived(&data, receiveData) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get pkg name fail");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransServerOnQosEvent(const char *pkgName, const QosParam *param)
{
    if (pkgName == NULL || param == NULL || param->tvCount <= 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ClientIpcOnChannelQosEvent(pkgName, param) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "ClientIpcOnChannelQosEvent fail");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelBind(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
{
    if (pkgName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "pkgName is null channelId=%{public}d", channelId);
        return SOFTBUS_INVALID_PARAM;
    }
    ChannelMsg data = {
        .msgChannelId = channelId,
        .msgChannelType = channelType,
        .msgPid = pid,
        .msgPkgName = pkgName,
        .msgUuid = NULL,
        .msgUdid = NULL
    };
    int32_t ret = ClientIpcOnChannelBind(&data);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel bind fail, ret=%{public}d, channelId=%{public}d", ret, channelId);
        return ret;
    }
    char *anonymizePkgName = NULL;
    Anonymize(pkgName, &anonymizePkgName);
    TRANS_LOGI(TRANS_CTRL,
        "trasn server on channel bind. pkgname=%{public}s, channelId=%{public}d, type=%{public}d",
        AnonymizeWrapper(anonymizePkgName), channelId, channelType);
    AnonymizeFree(anonymizePkgName);
    return SOFTBUS_OK;
}

IServerChannelCallBack *TransServerGetChannelCb(void)
{
    g_channelCallBack.OnChannelOpened = TransServerOnChannelOpened;
    g_channelCallBack.OnChannelClosed = TransServerOnChannelClosed;
    g_channelCallBack.OnChannelOpenFailed = TransServerOnChannelOpenFailed;
    g_channelCallBack.OnDataReceived = TransServerOnMsgReceived;
    g_channelCallBack.OnQosEvent = TransServerOnQosEvent;
    g_channelCallBack.GetPkgNameBySessionName = TransGetPkgNameBySessionName;
    g_channelCallBack.GetUidAndPidBySessionName = TransGetUidAndPid;
    g_channelCallBack.OnChannelBind = TransServerOnChannelBind;
    return &g_channelCallBack;
}

int32_t TransServerOnChannelLinkDown(const char *pkgName, int32_t pid, const LinkDownInfo *info)
{
    if (pkgName == NULL || info == NULL || info->networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGD(TRANS_CTRL, "pkgName=%{public}s", pkgName);

    ChannelMsg data = {
        .msgPid = pid,
        .msgPkgName = pkgName,
        .msgUuid = info->uuid,
        .msgUdid = info->udid
    };
    if (ClientIpcOnChannelLinkDown(&data, info->networkId, info->peerIp, info->routeType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel link down fail");
        return SOFTBUS_IPC_ERR;
    }
    return SOFTBUS_OK;
}

