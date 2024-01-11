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

#include "softbus_adapter_hitrace.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_hisysevt_transreporter.h"
#include "trans_client_proxy.h"
#include "trans_lane_manager.h"
#include "trans_log.h"
#include "trans_session_manager.h"
#include "softbus_qos.h"
#include "trans_event.h"

static IServerChannelCallBack g_channelCallBack;

static int32_t TransServerOnChannelOpened(const char *pkgName, int32_t pid, const char *sessionName,
    const ChannelInfo *channel)
{
    if (pkgName == NULL || sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (!channel->isServer && channel->channelType == CHANNEL_TYPE_UDP &&
        NotifyQosChannelOpened(channel) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_QOS, "NotifyQosChannelOpened failed.");
        return SOFTBUS_ERR;
    }
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
        .socketName = sessionName
    };
    if (channel->isServer) {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL_SERVER, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    } else {
        TRANS_EVENT(EVENT_SCENE_OPEN_CHANNEL, EVENT_STAGE_OPEN_CHANNEL_END, extra);
    }
    SoftbusRecordOpenSessionKpi(pkgName, channel->linkType, SOFTBUS_EVT_OPEN_SESSION_SUCC, timediff);
    SoftbusHitraceStop();
    return ClientIpcOnChannelOpened(pkgName, sessionName, channel, pid);
}

static int32_t TransServerOnChannelClosed(const char *pkgName, int32_t pid, int32_t channelId, int32_t channelType)
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
    if (ClientIpcOnChannelOpenFailed(&data, errCode) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "client ipc on channel open fail");
        return SOFTBUS_ERR;
    }
    SoftbusHitraceStop();
    TRANS_LOGW(TRANS_CTRL,
        "trasn server on channel open failed. pkgname=%{public}s, channId=%{public}d, type=%{public}d",
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
    TRANS_LOGW(TRANS_CTRL, "TransServerOnChannelLinkDown: pkgName=%{public}s", pkgName);

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

