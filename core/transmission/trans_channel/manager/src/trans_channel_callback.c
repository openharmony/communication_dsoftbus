/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "trans_client_proxy.h"
#include "trans_lane_manager.h"
#include "trans_session_manager.h"

static IServerChannelCallBack g_channelCallBack;

static int32_t TransServerOnChannelOpened(const char *pkgName, const char *sessionName,
    const ChannelInfo *channel)
{
    if (pkgName == NULL || sessionName == NULL || channel == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    return ClientIpcOnChannelOpened(pkgName, sessionName, channel);
}

static int32_t TransServerOnChannelClosed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (TransLaneMgrDelLane(channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "delete lane object failed.");
    }
    if (ClientIpcOnChannelClosed(pkgName, channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify fail");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int32_t TransServerOnChannelOpenFailed(const char *pkgName, int32_t channelId, int32_t channelType)
{
    if (pkgName == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (TransLaneMgrDelLane(channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN, "delete lane object failed.");
    }
    if (ClientIpcOnChannelOpenFailed(pkgName, channelId, channelType) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify fail");
        return SOFTBUS_ERR;
    }
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_WARN,
        "trasn server on channel open failed.[pkgname=%s][channid=%d][type=%d]", pkgName, channelId, channelType);
    return SOFTBUS_OK;
}

static int32_t TransServerOnMsgReceived(const char *pkgName, int32_t channelId, int32_t channelType,
    const void *data, uint32_t len, int32_t type)
{
    if (pkgName == NULL || data == NULL || len == 0) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (ClientIpcOnChannelMsgReceived(pkgName, channelId, channelType, data, len, type) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get pkg name fail");
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
    g_channelCallBack.GetPkgNameBySessionName = TransGetPkgNameBySessionName;
    g_channelCallBack.GetUidAndPidBySessionName = TransGetUidAndPid;
    return &g_channelCallBack;
}
