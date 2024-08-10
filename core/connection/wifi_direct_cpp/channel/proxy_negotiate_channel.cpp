/*
 * Copyright (c) 2024 Huawei Device Co., Ltd.
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

#include "proxy_negotiate_channel.h"

#include "conn_log.h"
#include "softbus_error_code.h"
#include "softbus_proxychannel_pipeline.h"

#include "command/negotiate_command.h"
#include "data/negotiate_message.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_scheduler_factory.h"

namespace OHOS::SoftBus {

constexpr int MAX_COC_PROXY_DATA_LEN = 1024;

static void OnDataReceived(int32_t channelId, const char *data, uint32_t len)
{
    CONN_CHECK_AND_RETURN_LOGW(data != nullptr && len != 0, CONN_WIFI_DIRECT, "data invalid");
    CONN_CHECK_AND_RETURN_LOGW(len <= MAX_COC_PROXY_DATA_LEN, CONN_WIFI_DIRECT, "data too large");
    CONN_LOGI(CONN_WIFI_DIRECT, "len=%{public}u", len);

    ProtocolType type { ProtocolType::JSON };
    auto channel = std::make_shared<CoCProxyNegotiateChannel>(channelId);
    auto remoteDeviceId = channel->GetRemoteDeviceId();
    if (WifiDirectUtils::IsLocalSupportTlv() && WifiDirectUtils::IsRemoteSupportTlv(remoteDeviceId)) {
        type = ProtocolType::TLV;
    }

    auto protocol = WifiDirectProtocolFactory::CreateProtocol(type);
    std::vector<uint8_t> input;
    input.insert(input.end(), data, data + len);
    NegotiateMessage msg;
    msg.Unmarshalling(*protocol, input);
    msg.SetRemoteDeviceId(remoteDeviceId);

    NegotiateCommand command(msg, channel);
    CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessNegotiateData(remoteDeviceId, command);
}

static void OnDisconnected(int32_t channelId)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "channelId=%{public}d", channelId);
}

int CoCProxyNegotiateChannel::Init()
{
    CONN_LOGI(CONN_INIT, "enter");
    ITransProxyPipelineListener listener = {
        .onDataReceived = OnDataReceived,
        .onDisconnected = OnDisconnected,
    };

    int32_t ret = TransProxyPipelineRegisterListener(MSG_TYPE_P2P_NEGO, &listener);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "register proxy channel listener failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

CoCProxyNegotiateChannel::CoCProxyNegotiateChannel(int32_t channelId) : channelId_(channelId)
{
    char remoteUuid[UUID_BUF_LEN] {};
    if (TransProxyPipelineGetUuidByChannelId(channelId, remoteUuid, UUID_BUF_LEN) != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "auth get uuid failed");
        return;
    }
    remoteDeviceId_ = remoteUuid;
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
}

CoCProxyNegotiateChannel::~CoCProxyNegotiateChannel()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
}

bool CoCProxyNegotiateChannel::operator==(const CoCProxyNegotiateChannel &other) const
{
    return channelId_ == other.channelId_;
}

int CoCProxyNegotiateChannel::SendMessage(const NegotiateMessage &msg) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
    ProtocolType type { ProtocolType::JSON };
    if (WifiDirectUtils::IsLocalSupportTlv() && WifiDirectUtils::IsRemoteSupportTlv(remoteDeviceId_)) {
        type = ProtocolType::TLV;
    }
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(type);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        protocol != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "create protocol failed");
    std::vector<uint8_t> output;
    msg.Marshalling(*protocol, output);

    auto ret = TransProxyPipelineSendMessage(
        channelId_, output.data(), static_cast<uint32_t>(output.size()), MSG_TYPE_P2P_NEGO);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "post data failed");

    return SOFTBUS_OK;
}

std::string CoCProxyNegotiateChannel::GetRemoteDeviceId() const
{
    return remoteDeviceId_;
}

} // namespace OHOS::SoftBus
