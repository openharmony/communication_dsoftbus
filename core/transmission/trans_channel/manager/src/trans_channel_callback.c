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

#include "trans_channel_callback.h"
#include "bus_center_info_key.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_adapter_hitrace.h"
#include "softbus_app_info.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "softbus_qos.h"
#include "trans_channel_common.h"
#include "trans_client_proxy.h"
#include "trans_event.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"

static IServerChannelCallBack g_channelCallBack;

static int32_t TransServerOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    if (pkgName == NULL || sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    char peerUdid[DEVICE_ID_SIZE_MAX] = { 0 };
    GetRemoteUdidWithNetworkId(channel->peerDeviceId, peerUdid, sizeof(peerUdid));
    int32_t osType = 0;
    GetOsTypeByNetworkId(channel->peerDeviceId, &osType);
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
        .osType = osType,
        .peerUdid = peerUdid
    };
    CoreSessionState state = CORE_SESSION_STATE_INIT;
    TransGetSocketChannelStateByChannel(channel->channelId, channel->channelType, &state);
    if (state == CORE_SESSION_STATE_CANCELLING) {
        char *tmpSessionName = NULL;
        Anonymize(sessionName, &tmpSessionName);
        TRANS_LOGW(TRANS_CTRL,
            "Cancel bind process, sesssionName=%{public}s, channelId=%{public}d", tmpSessionName, channel->channelId);
        AnonymizeFree(tmpSessionName);
        extra.result = EVENT_STAGE_RESULT_CANCELED;
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
        return SOFTBUS_TRANS_STOP_BIND_BY_CANCEL;
    }
    if (!channel->isServer && channel->channelType == CHANNEL_TYPE_UDP &&
        NotifyQosChannelOpened(channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "NotifyQosChannelOpened failed.");
        return SOFTBUS_ERR;
    }
    if (channel->isServer) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
    SoftbusRecordOpenSessionKpi(pkgName, channel->linkType, SOFTBUS_EVT_OPEN_SESSION_SUCC, timediff);
    SoftbusHitraceStop();
    TransSetSocketChannelStateByChannel(channel->channelId, channel->channelType, CORE_SESSION_STATE_CHANNEL_OPENED);
    return ClientIpcOnChannelOpened(pkgName, sessionName, channel, pid);
}

static int32_t TransServerOnChannelClosed(
    const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType, int32_t messageType)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (TransLaneMgrDelLane(channelId, channelType) != SOFTBUS_OK) {
        TRANS_LOGW(TRANS_CTRL, "delete lane object failed.");
    }
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
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelOpenFailed(const char *pkgName, int32_t pid, int32_t channelId,
    int32_t channelType, int32_t errCode)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (TransLaneMgrDelLane(channelId, channelType) != SOFTBUS_OK) {
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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
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
        return SOFTBUS_ERR;
    }
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
    return &g_channelCallBack;
}

int32_t TransServerOnChannelLinkDown(const char *pkgName, int32_t pid, const char *uuid,
    const char *udid, const char *peerIp, const char *networkId, int32_t routeType)
{
    if (pkgName == NULL || networkId == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    TRANS_LOGD(TRANS_CTRL, "pkgName=%{public}s", pkgName);

    ChannelMsg data = {
        .msgPid = pid,
        .msgPkgName = pkgName,
        .msgUuid = uuid,
        .msgUdid = udid
    };
    if (ClientIpcOnChannelLinkDown(&data, networkId, peerIp, routeType) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel link down fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

