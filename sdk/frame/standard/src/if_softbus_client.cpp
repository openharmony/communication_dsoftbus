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

#include "if_softbus_client.h"
#include "softbus_log.h"
#include "softbus_error_code.h"

namespace OHOS {
void ISoftBusClient::OnDeviceFound(const DeviceInfo *device)
{
    MLOGI("ipc default impl");
}

void ISoftBusClient::OnDiscoverFailed(int subscribeId, int failReason)
{
    MLOGI("ipc default impl");
}

void ISoftBusClient::OnDiscoverySuccess(int subscribeId)
{
    MLOGI("ipc default impl");
}
void ISoftBusClient::OnPublishSuccess(int publishId)
{
    MLOGI("ipc default impl");
}

void ISoftBusClient::OnPublishFail(int publishId, int reason)
{
    MLOGI("ipc default impl");
}

int32_t ISoftBusClient::OnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
                                             uint32_t len, int32_t type)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelClosed(int32_t channelId, int32_t channelType)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
                                          const QosTv *tvList)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnLeaveLNNResult(const char *networkId, int retCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeOnlineStateChanged(bool isOnline, void *info, uint32_t infoTypeLen)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeBasicInfoChanged(void *info, uint32_t infoTypeLen, int32_t type)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    MLOGI("ipc default impl");
    return SOFTBUS_OK;
}

void ISoftBusClient::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    MLOGI("ipc default impl");
}

void ISoftBusClient::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    MLOGI("ipc default impl");
}

void ISoftBusClient::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    MLOGI("ipc default impl");
}
} // namespace OHOS