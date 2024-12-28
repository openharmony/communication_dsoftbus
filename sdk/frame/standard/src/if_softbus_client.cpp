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

#include "comm_log.h"
#include "if_softbus_client.h"
#include "softbus_error_code.h"

namespace OHOS {
int32_t ISoftBusClient::OnChannelOpened(const char *sessionName, const ChannelInfo *channel)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelOpenFailed(int32_t channelId, int32_t channelType, int32_t errCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelLinkDown(const char *networkId, int32_t routeType)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelMsgReceived(int32_t channelId, int32_t channelType, const void *data,
                                             uint32_t len, int32_t type)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelClosed(int32_t channelId, int32_t channelType, int32_t messageType)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelQosEvent(int32_t channelId, int32_t channelType, int32_t eventId, int32_t tvCount,
                                          const QosTv *tvList)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::SetChannelInfo(const char *sessionName, int32_t sessionId,
                                       int32_t channelId, int32_t channelType)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnJoinLNNResult(void *addr, uint32_t addrTypeLen, const char *networkId, int retCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnJoinMetaNodeResult(void *addr, uint32_t addrTypeLen, void *metaInfo, uint32_t infoLen,
                                             int retCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnLeaveLNNResult(const char *networkId, int retCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnLeaveMetaNodeResult(const char *networkId, int retCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeOnlineStateChanged(const char *pkgName, bool isOnline, void *info, uint32_t infoTypeLen)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeBasicInfoChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeStatusChanged(const char *pkgName, void *info, uint32_t infoTypeLen, int32_t type)
{
    (void)pkgName;
    (void)info;
    (void)infoTypeLen;
    (void)type;
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnLocalNetworkIdChanged(const char *pkgName)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnNodeDeviceTrustedChange(const char *pkgName, int32_t type, const char *msg, uint32_t msgLen)
{
    (void)pkgName;
    (void)type;
    (void)msg;
    (void)msgLen;
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnHichainProofException(
    const char *pkgName, const char *proofInfo, uint32_t proofLen, uint16_t deviceTypeId, int32_t errCode)
{
    (void)pkgName;
    (void)proofInfo;
    (void)proofLen;
    (void)deviceTypeId;
    (void)errCode;
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnTimeSyncResult(const void *info, uint32_t infoTypeLen, int32_t retCode)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

void ISoftBusClient::OnPublishLNNResult(int32_t publishId, int32_t reason)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
}

void ISoftBusClient::OnRefreshLNNResult(int32_t refreshId, int32_t reason)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
}

void ISoftBusClient::OnRefreshDeviceFound(const void *device, uint32_t deviceLen)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
}

void ISoftBusClient::OnDataLevelChanged(const char *networkId, const DataLevelInfo *dataLevelInfo)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
}

int32_t ISoftBusClient::OnClientTransLimitChange(int32_t channelId, uint8_t tos)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnChannelBind(int32_t channelId, int32_t channelType)
{
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnClientChannelOnQos(
    int32_t channelId, int32_t channelType, QoSEvent event, const QosTV *qos, uint32_t count)
{
    (void)channelId;
    (void)channelType;
    (void)event;
    (void)qos;
    (void)count;
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}

int32_t ISoftBusClient::OnCheckCollabRelation(
    const CollabInfo *sourceInfo, const CollabInfo *sinkInfo, int32_t channelId, int32_t channelType)
{
    (void)sourceInfo;
    (void)sinkInfo;
    (void)channelId;
    (void)channelType;
    COMM_LOGI(COMM_EVENT, "ipc default impl");
    return SOFTBUS_OK;
}
} // namespace OHOS
