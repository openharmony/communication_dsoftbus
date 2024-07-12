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

#include "auth_negotiate_channel.h"
#include "securec.h"

#include "conn_log.h"
#include "lnn_distributed_net_ledger.h"
#include "softbus_error_code.h"

#include "wifi_direct_scheduler.h"
#include "wifi_direct_scheduler_factory.h"
#include "command/negotiate_command.h"
#include "data/link_manager.h"
#include "entity/entity_factory.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"

namespace OHOS::SoftBus {
AuthNegotiateChannel::AuthNegotiateChannel(const AuthHandle &handle)
    : handle_(handle), close_(false)
{
    char remoteUuid[UUID_BUF_LEN] {};
    auto ret = AuthGetDeviceUuid(handle_.authId, remoteUuid, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "auth get device id failed");
    remoteDeviceId_ = remoteUuid;
    auto remoteNetworkId = WifiDirectUtils::UuidToNetworkId(remoteUuid);
    if (!WifiDirectUtils::IsDeviceOnline(remoteNetworkId)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "diff account");
        remoteDeviceId_ = "";
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
}

AuthNegotiateChannel::~AuthNegotiateChannel()
{
    if (close_) {
        CONN_LOGI(CONN_WIFI_DIRECT, "close auth");
        AuthCloseConn(handle_);
    }
}

bool AuthNegotiateChannel::operator==(const AuthNegotiateChannel &other) const
{
    return handle_.authId == other.handle_.authId && handle_.type == other.handle_.type;
}

bool AuthNegotiateChannel::IsMeta() const
{
    bool isMeta = false;
    int32_t ret = AuthGetMetaType(handle_.authId, &isMeta);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get meta type failed");
    return isMeta;
}

void AuthNegotiateChannel::SetClose()
{
    close_ = true;
}

std::string AuthNegotiateChannel::GetRemoteDeviceId() const
{
    return remoteDeviceId_;
}

static int64_t GenerateSequence()
{
    static int64_t wifiDirectTransferSequence = 0;

    if (wifiDirectTransferSequence < 0) {
        wifiDirectTransferSequence = 0;
    }
    return wifiDirectTransferSequence++;
}

int AuthNegotiateChannel::SendMessage(const NegotiateMessage &msg) const
{
    CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
    ProtocolType type { ProtocolType::TLV };
    if (!remoteDeviceId_.empty() && (!WifiDirectUtils::IsLocalSupportTlv() ||
        !WifiDirectUtils::IsRemoteSupportTlv(remoteDeviceId_))) {
        type = ProtocolType::JSON;
    }
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(type);
    std::vector<uint8_t> output;
    msg.Marshalling(*protocol, output);

    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .seq = GenerateSequence(),
        .len = static_cast<uint32_t>(output.size()),
        .data = output.data(),
    };
    auto result = AuthPostTransData(handle_, &dataInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(
        result == SOFTBUS_OK, SOFTBUS_CONN_AUTH_POST_DATA_FAILED, CONN_WIFI_DIRECT, "post data failed");
    return SOFTBUS_OK;
}

static void OnAuthDataReceived(AuthHandle handle, const AuthTransData *data)
{
    ProtocolType type { ProtocolType::TLV };
    auto channel = std::make_shared<AuthNegotiateChannel>(handle);
    auto remoteDeviceId = channel->GetRemoteDeviceId();
    if (!remoteDeviceId.empty() && (!WifiDirectUtils::IsLocalSupportTlv() ||
        !WifiDirectUtils::IsRemoteSupportTlv(remoteDeviceId))) {
        type = ProtocolType::JSON;
    }
    auto protocol = WifiDirectProtocolFactory::CreateProtocol(type);
    std::vector<uint8_t> input;
    input.insert(input.end(), data->data, data->data + data->len);
    NegotiateMessage msg;
    msg.Unmarshalling(*protocol, input);
    if (remoteDeviceId.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use remote mac as device id");
        remoteDeviceId = msg.GetLinkInfo().GetRemoteBaseMac();
    }
    msg.SetRemoteDeviceId(remoteDeviceId);

    NegotiateCommand command(msg, channel);
    CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessNegotiateData(remoteDeviceId, command);
}

static void OnAuthDisconnected(AuthHandle authHandle)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d authId=%{public}" PRId64, authHandle.type, authHandle.authId);
    AuthNegotiateChannel disconnectChannel(authHandle);
    InnerLink::LinkType type = InnerLink::LinkType::INVALID_TYPE;
    std::string remoteDeviceId;
    std::string remoteMac;
    LinkManager::GetInstance().ForEach(
        [&disconnectChannel, &type, &remoteDeviceId, &remoteMac] (const InnerLink &innerLink) {
            auto channel = std::dynamic_pointer_cast<AuthNegotiateChannel>(innerLink.GetNegotiateChannel());
            if (channel != nullptr && disconnectChannel == *channel) {
                type = innerLink.GetLinkType();
                remoteDeviceId= innerLink.GetRemoteDeviceId();
                remoteMac = innerLink.GetRemoteBaseMac();
                return true;
            }
            return false;
        });

    CONN_LOGI(CONN_WIFI_DIRECT, "disconnect type=%{public}d, remoteUuid=%{public}s, remoteMac=%{public}s",
        static_cast<int>(type), WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(),
        WifiDirectAnonymizeMac(remoteMac).c_str());
    if (type != InnerLink::LinkType::INVALID_TYPE) {
        LinkManager::GetInstance().RemoveLink(type, remoteDeviceId);
        auto &entity = EntityFactory::GetInstance().GetEntity(type);
        entity.DisconnectLink(remoteMac);
        entity.DestoryGroupIfNeeded();
    }
}

static void OnAuthException(AuthHandle authHandle, int32_t error)
{
    auto channel = std::make_shared<AuthNegotiateChannel>(authHandle);
    auto remoteDeviceId = channel->GetRemoteDeviceId();
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s auth exception error=%{public}d",
        WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(), error);
    AuthExceptionEvent event { error, authHandle };
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

void AuthNegotiateChannel::Init()
{
    CONN_LOGI(CONN_INIT, "enter");
    AuthTransListener authListener = {
        .onDataReceived = OnAuthDataReceived,
        .onDisconnected = OnAuthDisconnected,
        .onException = OnAuthException,
    };

    int32_t ret = RegAuthTransListener(MODULE_P2P_LINK, &authListener);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_INIT, "register auth transfer listener failed");
}

std::pair<int, ListenerModule> AuthNegotiateChannel::StartListening(
    AuthLinkType type, const std::string &localIp, int port)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, localIp=%{public}s, port=%{public}d", type,
              WifiDirectAnonymizeIp(localIp).c_str(), port);
    ListenerModule module;
    auto resultPort = AuthStartListeningForWifiDirect(type, localIp.c_str(), port, &module);
    CONN_LOGI(CONN_WIFI_DIRECT, "resultPort=%{public}d, module=%{public}d", resultPort, module);
    return { resultPort, module };
}

void AuthNegotiateChannel::StopListening(AuthLinkType type, ListenerModule module)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, moduleId=%{public}d", type, module);
    AuthStopListeningForWifiDirect(type, module);
}

void AuthNegotiateChannel::OnConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    std::string remoteDeviceId;
    {
        std::lock_guard lock(lock_);
        remoteDeviceId = requestIdToDeviceIdMap_[requestId];
        requestIdToDeviceIdMap_.erase(requestId);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}u remoteDeviceId=%{public}s", requestId,
        WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
    AuthOpenEvent event { SOFTBUS_OK, authHandle };
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

void AuthNegotiateChannel::OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    std::string remoteDeviceId;
    {
        std::lock_guard lock(lock_);
        remoteDeviceId = requestIdToDeviceIdMap_[requestId];
        requestIdToDeviceIdMap_.erase(requestId);
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "requestId=%{public}u remoteDeviceId=%{public}s reason=%{public}d", requestId,
        WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(), reason);
    AuthOpenEvent event { reason };
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

int AuthNegotiateChannel::OpenConnection(const OpenParam &param, const std::shared_ptr<AuthNegotiateChannel> &channel)
{
    bool isMeta = false;
    bool needUdid = true;
    if (channel != nullptr) {
        isMeta = channel->IsMeta();
    }
    if (param.remoteUuid.length() < UUID_BUF_LEN - 1) {
        isMeta = true;
        needUdid = false;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "remoteUuid=%{public}s, remoteIp=%{public}s, remotePort=%{public}d, isMeta=%{public}d",
        WifiDirectAnonymizeDeviceId(param.remoteUuid).c_str(), WifiDirectAnonymizeIp(param.remoteIp).c_str(),
        param.remotePort, isMeta);

    AuthConnInfo authConnInfo {};
    authConnInfo.type = param.type;
    authConnInfo.info.ipInfo.port = param.remotePort;
    authConnInfo.info.ipInfo.moduleId = param.module;
    if (isMeta && needUdid) {
        authConnInfo.info.ipInfo.authId = channel->handle_.authId;
    }
    auto ret = strcpy_s(authConnInfo.info.ipInfo.ip, IP_LEN, param.remoteIp.c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == EOK, SOFTBUS_CONN_OPEN_CONNECTION_COPY_IP_FAILED, CONN_WIFI_DIRECT, "copy ip failed");
    if (needUdid) {
        const char *remoteUdid = LnnConvertDLidToUdid(param.remoteUuid.c_str(), CATEGORY_UUID);
        CONN_CHECK_AND_RETURN_RET_LOGE(remoteUdid != nullptr && strlen(remoteUdid) != 0,
            SOFTBUS_CONN_OPEN_CONNECTION_GET_REMOTE_UUID_FAILED, CONN_WIFI_DIRECT, "get remote udid failed");
        ret = strcpy_s(authConnInfo.info.ipInfo.udid, UDID_BUF_LEN, remoteUdid);
        CONN_CHECK_AND_RETURN_RET_LOGE(
            ret == EOK, SOFTBUS_CONN_OPEN_CONNECTION_COPY_UUID_FAILED, CONN_WIFI_DIRECT, "copy udid failed");
    }

    AuthConnCallback authConnCallback = {
        .onConnOpened = AuthNegotiateChannel::OnConnOpened,
        .onConnOpenFailed = AuthNegotiateChannel::OnConnOpenFailed,
    };

    auto requestId = AuthGenRequestId();
    {
        std::lock_guard lock(lock_);
        requestIdToDeviceIdMap_[requestId] = param.remoteUuid;
    }

    ret = AuthOpenConn(&authConnInfo, requestId, &authConnCallback, isMeta);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "auth open connect failed, error=%{public}d", ret);
        std::lock_guard lock(lock_);
        requestIdToDeviceIdMap_.erase(requestId);
    }
    return ret;
}
} // namespace OHOS::SoftBus
