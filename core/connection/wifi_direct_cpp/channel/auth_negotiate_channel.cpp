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

#include "securec.h"
#include "auth_negotiate_channel.h"
#include "command/negotiate_command.h"
#include "common_timer_errors.h"
#include "conn_log.h"
#include "data/link_manager.h"
#include "dfx/wifi_direct_dfx.h"
#include "entity/entity_factory.h"
#include "lnn_distributed_net_ledger.h"
#include "protocol/wifi_direct_protocol_factory.h"
#include "softbus_error_code.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_scheduler.h"
#include "wifi_direct_scheduler_factory.h"

namespace OHOS::SoftBus {
static constexpr int TIMER_TIMEOUT = 50;
static constexpr int WAIT_DETECT_RESPONSE_TIMEOUT_MS = 1000;
static constexpr int MAX_AUTH_DATA_LEN = 131072;
Utils::Timer AuthNegotiateChannel::timer_("DetectLink", TIMER_TIMEOUT);

AuthNegotiateChannel::AuthNegotiateChannel(const AuthHandle &handle)
    : handle_(handle), timerId_(Utils::TIMER_ERR_INVALID_VALUE), close_(false)
{
    char remoteUuid[UUID_BUF_LEN] {};
    auto ret = AuthGetDeviceUuid(handle_.authId, remoteUuid, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "auth get device id failed");
    remoteDeviceId_ = remoteUuid;
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

bool AuthNegotiateChannel::operator==(const AuthHandle &otherHandle) const
{
    return handle_.authId == otherHandle.authId && handle_.type == otherHandle.type;
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
    CONN_CHECK_AND_RETURN_RET_LOGE(
        protocol != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "create protocol failed");
    std::vector<uint8_t> output;
    msg.Marshalling(*protocol, output);

    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .seq = GenerateSequence(),
        .len = static_cast<uint32_t>(output.size()),
        .data = output.data(),
    };

    CONN_CHECK_AND_RETURN_RET_LOGE(
        AuthPostTransData(handle_, &dataInfo) == SOFTBUS_OK, SOFTBUS_CONN_AUTH_POST_DATA_FAILED,
        CONN_WIFI_DIRECT, "post data failed");
    return SOFTBUS_OK;
}

void AuthNegotiateChannel::OnWaitDetectResponseTimeout()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "timeout");
    {
        std::lock_guard lock(channelLock_);
        authIdToChannelMap_.erase(handle_.authId);
        if (authIdToChannelMap_.empty()) {
            CONN_LOGI(CONN_WIFI_DIRECT, "shutdown timer");
            timer_.Shutdown(true);
        }
    }

    NegotiateMessage response(NegotiateMessageType::CMD_DETECT_LINK_RSP);
    response.SetResultCode(SOFTBUS_TIMOUT);
    promise_->set_value(response);
}

NegotiateMessage AuthNegotiateChannel::SendMessageAndWaitResponse(const NegotiateMessage &msg)
{
    auto ret = SendMessage(msg);
    if (ret != SOFTBUS_OK) {
        NegotiateMessage response(NegotiateMessageType::CMD_DETECT_LINK_RSP);
        response.SetResultCode(ret);
        return response;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "send detect link request success");
    {
        std::lock_guard lock(channelLock_);
        promise_ = std::make_shared<std::promise<NegotiateMessage>>();
        if (authIdToChannelMap_.empty()) {
            CONN_LOGI(CONN_WIFI_DIRECT, "setup timer");
            timer_.Setup();
        }
        timerId_ = timer_.Register([this] () {
            std::thread(&AuthNegotiateChannel::OnWaitDetectResponseTimeout, this).detach();
        }, WAIT_DETECT_RESPONSE_TIMEOUT_MS, true);
        authIdToChannelMap_[handle_.authId] = shared_from_this();
    }

    return promise_->get_future().get();
}

void AuthNegotiateChannel::ProcessDetectLinkRequest(const std::shared_ptr<AuthNegotiateChannel> &channel)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "send detect link response");
    NegotiateMessage response(NegotiateMessageType::CMD_DETECT_LINK_RSP);
    response.SetResultCode(SOFTBUS_OK);
    channel->SendMessage(response);
}

void AuthNegotiateChannel::ProcessDetectLinkResponse(AuthHandle handle, const NegotiateMessage &response)
{
    std::lock_guard lock(channelLock_);
    auto it = authIdToChannelMap_.find(handle.authId);
    if (it == authIdToChannelMap_.end()) {
        CONN_LOGE(CONN_WIFI_DIRECT, "not find channel by authId=%{public}" PRId64, handle.authId);
        return;
    }

    auto channel = it->second;
    timer_.Unregister(channel->timerId_);
    authIdToChannelMap_.erase(it);
    if (authIdToChannelMap_.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "shutdown timer");
        timer_.Shutdown(true);
    }
    channel->promise_->set_value(response);
}

static bool CheckSameAccount(const NegotiateMessage &msg)
{
    bool ret = true;
    switch (msg.GetMessageType()) {
        case NegotiateMessageType::CMD_V3_REQ:
        case NegotiateMessageType::CMD_V3_RSP:
        case NegotiateMessageType::CMD_V3_CUSTOM_PORT_REQ:
        case NegotiateMessageType::CMD_V3_CUSTOM_PORT_RSP:
        case NegotiateMessageType::CMD_AUTH_HAND_SHAKE:
        case NegotiateMessageType::CMD_AUTH_HAND_SHAKE_RSP:
        case NegotiateMessageType::CMD_CONN_V2_REQ_3:
        case NegotiateMessageType::CMD_CONN_V2_RESP_3:
            ret = msg.GetExtraData().empty() || msg.GetExtraData().front();
            break;
        default:
            ret = true;
            break;
    }
    return ret;
}

static void OnAuthDataReceived(AuthHandle handle, const AuthTransData *data)
{
    CONN_CHECK_AND_RETURN_LOGW(data != nullptr, CONN_WIFI_DIRECT, "invalid param, data is null");
    CONN_CHECK_AND_RETURN_LOGW(data->len <= MAX_AUTH_DATA_LEN, CONN_WIFI_DIRECT, "data len is invalid");
    CONN_CHECK_AND_RETURN_LOGW(data->data != nullptr, CONN_WIFI_DIRECT, "invalid param, data of data is null");
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

    WifiDirectDfx::ReportReceiveAuthLinkMsg(msg, channel->GetRemoteDeviceId());

    bool sameAccount = CheckSameAccount(msg);
    CONN_LOGI(CONN_WIFI_DIRECT, "sameAccount=%{public}d", sameAccount);
    if (!sameAccount) {
        CONN_LOGI(CONN_WIFI_DIRECT, "diff account, use remote mac as device id");
        remoteDeviceId = msg.GetLinkInfo().GetRemoteBaseMac();
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "msgType=%{public}s", msg.MessageTypeToString().c_str());
    if (msg.GetMessageType() == NegotiateMessageType::CMD_DETECT_LINK_REQ) {
        std::thread(AuthNegotiateChannel::ProcessDetectLinkRequest, channel).detach();
        return;
    } else if (msg.GetMessageType() == NegotiateMessageType::CMD_DETECT_LINK_RSP) {
        std::thread(AuthNegotiateChannel::ProcessDetectLinkResponse, handle, msg).detach();
        return;
    } else if (static_cast<int>(msg.GetMessageType()) ==
            static_cast<int>(LegacyCommandType::CMD_GC_WIFI_CONFIG_CHANGED) ||
        msg.GetLegacyP2pCommandType() == LegacyCommandType::CMD_GC_WIFI_CONFIG_CHANGED) {
        CONN_LOGI(CONN_WIFI_DIRECT, "do not process %{public}d", static_cast<int>(msg.GetMessageType()));
        return;
    }

    msg.SetRemoteDeviceId(remoteDeviceId);
    NegotiateCommand command(msg, channel);
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessNegotiateData(remoteDeviceId, command);
}

static void OnAuthDisconnected(AuthHandle authHandle)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d authId=%{public}" PRId64, authHandle.type, authHandle.authId);
    AuthNegotiateChannel disconnectChannel(authHandle);
    InnerLink::LinkType type = InnerLink::LinkType::INVALID_TYPE;
    std::string remoteDeviceId;
    std::string remoteMac;
    bool isLegacyReused = false;
    LinkManager::GetInstance().ForEach(
        [&disconnectChannel, &type, &remoteDeviceId, &remoteMac, &isLegacyReused] (const InnerLink &innerLink) {
            auto channel = std::dynamic_pointer_cast<AuthNegotiateChannel>(innerLink.GetNegotiateChannel());
            if (channel != nullptr && disconnectChannel == *channel) {
                type = innerLink.GetLinkType();
                remoteDeviceId= innerLink.GetRemoteDeviceId();
                remoteMac = innerLink.GetRemoteBaseMac();
                isLegacyReused = innerLink.GetLegacyReused();
                return true;
            }
            return false;
        });

    CONN_LOGI(CONN_WIFI_DIRECT, "disconnect type=%{public}d, remoteUuid=%{public}s, remoteMac=%{public}s",
        static_cast<int>(type), WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(),
        WifiDirectAnonymizeMac(remoteMac).c_str());
    if (type != InnerLink::LinkType::INVALID_TYPE) {
        LinkManager::GetInstance().RemoveLink(type, remoteDeviceId);
        if (!isLegacyReused) {
            auto &entity = EntityFactory::GetInstance().GetEntity(type);
            entity.DisconnectLink(remoteMac);
            entity.DestroyGroupIfNeeded();
        }
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

int AuthNegotiateChannel::OpenConnection(const OpenParam &param, const std::shared_ptr<AuthNegotiateChannel> &channel,
    uint32_t &authReqId)
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
    authReqId = requestId;
    return ret;
}

void AuthNegotiateChannel::StopCustomListening()
{
    AuthStopListening(AUTH_LINK_TYPE_RAW_ENHANCED_P2P);
}

void AuthNegotiateChannel::RemovePendingAuthReq(uint32_t authReqId)
{
    std::lock_guard lock(lock_);
    requestIdToDeviceIdMap_.erase(authReqId);
}
} // namespace OHOS::SoftBus
