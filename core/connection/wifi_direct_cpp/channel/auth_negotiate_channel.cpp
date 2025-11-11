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
#include "bus_center_event.h"
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
#include "wifi_direct_init.h"

namespace OHOS::SoftBus {
static constexpr int TIMER_TIMEOUT = 50;
static constexpr int WAIT_DETECT_RESPONSE_TIMEOUT_MS = 1000;
static constexpr int MAX_AUTH_DATA_LEN = 131072;
Utils::Timer AuthNegotiateChannel::timer_("DetectLink", TIMER_TIMEOUT);

AuthNegotiateChannel::AuthNegotiateChannel(const AuthHandle &handle)
    : handle_(handle), timerId_(Utils::TIMER_ERR_INVALID_VALUE), close_(false)
{
    char remoteUuid[UUID_BUF_LEN] {};
    auto ret = DBinderSoftbusServer::GetInstance().AuthGetDeviceUuid(handle_.authId, remoteUuid, UUID_BUF_LEN);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT, "auth get uuid fail");
    remoteDeviceId_ = remoteUuid;
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
}

AuthNegotiateChannel::~AuthNegotiateChannel()
{
    if (close_) {
        CONN_LOGI(CONN_WIFI_DIRECT, "close auth");
        DBinderSoftbusServer::GetInstance().AuthCloseConn(handle_);
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
    int32_t ret = DBinderSoftbusServer::GetInstance().AuthGetMetaType(handle_.authId, &isMeta);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, false, CONN_WIFI_DIRECT, "get meta type fail");
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
        protocol != nullptr, SOFTBUS_INVALID_PARAM, CONN_WIFI_DIRECT, "create protocol fail");
    std::vector<uint8_t> output;
    msg.Marshalling(*protocol, output);

    AuthTransData dataInfo = {
        .module = MODULE_P2P_LINK,
        .seq = GenerateSequence(),
        .len = static_cast<uint32_t>(output.size()),
        .data = output.data(),
    };

    CONN_CHECK_AND_RETURN_RET_LOGE(
        DBinderSoftbusServer::GetInstance().AuthPostTransData(handle_, &dataInfo) == SOFTBUS_OK,
        SOFTBUS_CONN_AUTH_POST_DATA_FAILED, CONN_WIFI_DIRECT, "post data fail");
    return SOFTBUS_OK;
}

void AuthNegotiateChannel::OnWaitDetectResponseTimeout()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "timeout");
    {
        std::lock_guard lock(channelLock_);
        auto it = authIdToChannelMap_.find(handle_.authId);
        if (it == authIdToChannelMap_.end()) {
            CONN_LOGE(CONN_WIFI_DIRECT, "not find channel by authId=%{public}" PRId64, handle_.authId);
            return;
        }
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

static bool CheckSameAccount(const NegotiateMessage &msg, const std::string &remoteDeviceId)
{
    // The default value of extradata carried in the CMD_CONN_V2_RESP_3 message of the 3.0 device is 0.
    auto remoteNetworkId = WifiDirectUtils::UuidToNetworkId(remoteDeviceId);
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteNetworkId=%{public}s", WifiDirectAnonymizeDeviceId(remoteNetworkId).c_str());
    int32_t osType = 0;
    if (DBinderSoftbusServer::GetInstance().LnnGetOsTypeByNetworkId(remoteNetworkId.c_str(), &osType) == SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remote osType is %{public}d", osType);
        // The osType of the remote device is not OH_OS_TYPE, the remote device uses the same account.
        CONN_CHECK_AND_RETURN_RET_LOGI(osType == OH_OS_TYPE, true, CONN_WIFI_DIRECT,
            "remote device version is not later than 4.x");
    }
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
        case NegotiateMessageType::CMD_RENEGOTIATE_REQ:
        case NegotiateMessageType::CMD_RENEGOTIATE_RESP:
        case NegotiateMessageType::CMD_TRIGGER_REQ:
        case NegotiateMessageType::CMD_TRIGGER_RESP:
        case NegotiateMessageType::CMD_ERROR_NOTIFICATION:
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

    bool sameAccount = CheckSameAccount(msg, remoteDeviceId);
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
    } else if (msg.GetMessageType() == NegotiateMessageType::CMD_REFRESH_AUTH_HANDLE) {
        LinkManager::GetInstance().RefreshAuthHandle(remoteDeviceId, channel);
        return;
    } else if (msg.GetMessageType() == NegotiateMessageType::CMD_DBAC_SYNC_DATA) {
        auto extraData = msg.GetExtraData();
        AuthNegotiateChannel::SyncDBACData(extraData);
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
            if (innerLink.GetNegotiateChannel() != nullptr &&
                innerLink.GetNegotiateChannel()->GetType() == NegotiateChannelType::AUTH_CHANNEL) {
                auto channel = std::static_pointer_cast<AuthNegotiateChannel>(innerLink.GetNegotiateChannel());
                if (channel != nullptr && disconnectChannel == *channel) {
                    type = innerLink.GetLinkType();
                    remoteDeviceId= innerLink.GetRemoteDeviceId();
                    remoteMac = innerLink.GetRemoteBaseMac();
                    isLegacyReused = innerLink.GetLegacyReused();
                    return true;
                }
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
    AuthTransListener authListener = {
        .onDataReceived = OnAuthDataReceived,
        .onDisconnected = OnAuthDisconnected,
        .onException = OnAuthException,
    };

    int32_t ret = DBinderSoftbusServer::GetInstance().RegAuthTransListener(MODULE_P2P_LINK, &authListener);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_INIT, "register auth transfer listener fail");
    ret = DBinderSoftbusServer::GetInstance().LnnRegisterEventHandler(LNN_EVENT_NOTIFY_RAW_ENHANCE_P2P,
        AddAuthConnection);
    CONN_CHECK_AND_RETURN_LOGW(ret == SOFTBUS_OK, CONN_INIT, "register lnn event fail, ret=%{public}d", ret);
}

std::pair<int, ListenerModule> AuthNegotiateChannel::StartListening(
    AuthLinkType type, const std::string &localIp, int port)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, localIp=%{public}s, port=%{public}d", type,
              WifiDirectAnonymizeIp(localIp).c_str(), port);
    ListenerModule module;
    auto resultPort = DBinderSoftbusServer::GetInstance().AuthStartListeningForWifiDirect(type, localIp.c_str(),
        port, &module);
    CONN_LOGI(CONN_WIFI_DIRECT, "resultPort=%{public}d, module=%{public}d", resultPort, module);
    return { resultPort, module };
}

void AuthNegotiateChannel::StopListening(AuthLinkType type, ListenerModule module)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "type=%{public}d, moduleId=%{public}d", type, module);
    DBinderSoftbusServer::GetInstance().AuthStopListeningForWifiDirect(type, module);
}

void AuthNegotiateChannel::OnConnOpened(uint32_t requestId, AuthHandle authHandle)
{
    AuthOpenEvent event { SOFTBUS_OK, authHandle };
    std::string remoteDeviceId;
    {
        std::lock_guard lock(lock_);
        remoteDeviceId = requestIdToDeviceIdMap_[requestId];
        CONN_LOGI(CONN_WIFI_DIRECT, "reqId=%{public}u remoteDeviceId=%{public}s", requestId,
            WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
        requestIdToDeviceIdMap_.erase(requestId);
        auto it = authOpenEventPromiseMap_.find(requestId);
        if (it != authOpenEventPromiseMap_.end()) {
            it->second->set_value(event);
            authOpenEventPromiseMap_.erase(requestId);
            return;
        }
    }
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

void AuthNegotiateChannel::OnConnOpenFailed(uint32_t requestId, int32_t reason)
{
    AuthOpenEvent event { reason };
    std::string remoteDeviceId;
    {
        std::lock_guard lock(lock_);
        remoteDeviceId = requestIdToDeviceIdMap_[requestId];
        CONN_LOGE(CONN_WIFI_DIRECT, "reqId=%{public}u remoteDeviceId=%{public}s reason=%{public}d", requestId,
            WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str(), reason);
        requestIdToDeviceIdMap_.erase(requestId);
        auto it = authOpenEventPromiseMap_.find(requestId);
        if (it != authOpenEventPromiseMap_.end()) {
            it->second->set_value(event);
            authOpenEventPromiseMap_.erase(requestId);
            return;
        }
    }
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().ProcessEvent(remoteDeviceId, event);
}

void AuthNegotiateChannel::AddAuthConnection(const LnnEventBasicInfo *info)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "start refresh auth connection");
    LnnNotifyRawEnhanceP2pEvent *lnnNotifyRawEnhanceP2pEvent =
        reinterpret_cast<LnnNotifyRawEnhanceP2pEvent *>(const_cast<LnnEventBasicInfo *>(info));
    std::string remoteUuid = lnnNotifyRawEnhanceP2pEvent->uuid;
    std::thread(AuthNegotiateChannel::RefreshAuthConnection, remoteUuid).detach();
}

void AuthNegotiateChannel::RefreshAuthConnection(std::string remoteUuid)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "start refresh auth connection, remoteUuid=%{public}s",
        WifiDirectAnonymizeDeviceId(remoteUuid).c_str());
    AuthNegotiateChannel::OpenParam param;
    param.type = AUTH_LINK_TYPE_ENHANCED_P2P;
    param.remoteUuid = remoteUuid;
    bool res = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::HML, remoteUuid, [&param, &remoteUuid](InnerLink &link) {
            if (link.GetRemoteDeviceId() == remoteUuid) {
                param.module = link.GetListenerModule();
                param.remoteIp = link.GetRemoteIpv4();
                param.remotePort = link.GetRemotePort();
                return true;
            }
            return false;
        });
    CONN_CHECK_AND_RETURN_LOGE(res, CONN_WIFI_DIRECT, "get param fail");
    CONN_CHECK_AND_RETURN_LOGE(param.remotePort > 0, CONN_WIFI_DIRECT, "remote port is zero");

    auto authOpenEventPromise = std::make_shared<std::promise<AuthOpenEvent>>();
    uint32_t authReqId = 0;
    auto ret = AuthNegotiateChannel::OpenConnection(param, nullptr, authReqId, authOpenEventPromise);
    CONN_CHECK_AND_RETURN_LOGE(ret == SOFTBUS_OK, CONN_WIFI_DIRECT,
        "open connection fail, ret=%{public}d", ret);
    auto authEvent = authOpenEventPromise->get_future().get();
    CONN_CHECK_AND_RETURN_LOGE(authEvent.reason_ == SOFTBUS_OK, CONN_WIFI_DIRECT,
        "open connection fail, ret=%{public}d", authEvent.reason_);
    auto channel = std::make_shared<AuthNegotiateChannel>(authEvent.handle_);
    LinkManager::GetInstance().RefreshAuthHandle(remoteUuid, channel);
    NegotiateMessage msg(NegotiateMessageType::CMD_REFRESH_AUTH_HANDLE);
    msg.SetRemoteDeviceId(remoteUuid);
    channel->SendMessage(msg);
}

int AuthNegotiateChannel::AssignValueForAuthConnInfo(bool isMeta, bool needUdid, const OpenParam &param,
    const std::shared_ptr<AuthNegotiateChannel> &channel, AuthConnInfo &authConnInfo)
{
    authConnInfo.type = param.type;
    authConnInfo.info.ipInfo.port = param.remotePort;
    authConnInfo.info.ipInfo.moduleId = param.module;
    if (isMeta && channel != nullptr) {
        authConnInfo.info.ipInfo.authId = channel->handle_.authId;
    }
    auto ret = strcpy_s(authConnInfo.info.ipInfo.ip, IP_LEN, param.remoteIp.c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == EOK, SOFTBUS_CONN_OPEN_CONNECTION_COPY_IP_FAILED, CONN_WIFI_DIRECT, "copy ip fail");
    if (needUdid) {
        char remoteUdid[UDID_BUF_LEN] = {0};
        int32_t result = DBinderSoftbusServer::GetInstance().LnnConvertDLidToUdid(param.remoteUuid.c_str(),
            CATEGORY_UUID, remoteUdid, UDID_BUF_LEN);
        CONN_CHECK_AND_RETURN_RET_LOGE(result == SOFTBUS_OK,
            SOFTBUS_CONN_OPEN_CONNECTION_GET_REMOTE_UUID_FAILED, CONN_WIFI_DIRECT, "get remote udid fail");
        ret = strcpy_s(authConnInfo.info.ipInfo.udid, UDID_BUF_LEN, remoteUdid);
        CONN_CHECK_AND_RETURN_RET_LOGE(
            ret == EOK, SOFTBUS_CONN_OPEN_CONNECTION_COPY_UUID_FAILED, CONN_WIFI_DIRECT, "copy udid fail");
    }
    return SOFTBUS_OK;
}

int AuthNegotiateChannel::AuthOpenConnection(uint32_t requestId, AuthConnInfo authConnInfo, bool isMeta)
{
    AuthConnCallback authConnCallback = {
        .onConnOpened = AuthNegotiateChannel::OnConnOpened,
        .onConnOpenFailed = AuthNegotiateChannel::OnConnOpenFailed,
    };

    return DBinderSoftbusServer::GetInstance().AuthOpenConn(&authConnInfo, requestId, &authConnCallback, isMeta);
}

int AuthNegotiateChannel::OpenConnection(const OpenParam &param, const std::shared_ptr<AuthNegotiateChannel> &channel,
    uint32_t &authReqId, std::shared_ptr<std::promise<AuthOpenEvent>> authOpenEventPromise)
{
    bool isMeta = channel != nullptr ? channel->IsMeta() : false;
    bool needUdid = true;
    if (param.remoteUuid.length() < UUID_BUF_LEN - 1) {
        isMeta = true;
        needUdid = false;
    }
    if (isMeta && param.type == AUTH_LINK_TYPE_P2P) {
        needUdid = false;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "remoteUuid=%{public}s, remoteIp=%{public}s, remotePort=%{public}d, "
                                "isMeta=%{public}d, needUdid=%{public}d",
        WifiDirectAnonymizeDeviceId(param.remoteUuid).c_str(), WifiDirectAnonymizeIp(param.remoteIp).c_str(),
        param.remotePort, isMeta, needUdid);

    AuthConnInfo authConnInfo {};
    auto ret = AssignValueForAuthConnInfo(isMeta, needUdid, param, channel, authConnInfo);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "assign value for auth conn info fail");

    auto requestId = DBinderSoftbusServer::GetInstance().AuthGenRequestId();
    {
        std::lock_guard lock(lock_);
        requestIdToDeviceIdMap_[requestId] = param.remoteUuid;
        if (authOpenEventPromise != nullptr) {
            authOpenEventPromiseMap_[requestId] = authOpenEventPromise;
        }
    }
    authReqId = requestId;
    ret = AuthOpenConnection(requestId, authConnInfo, isMeta);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "auth open connect fail, ret=%{public}d", ret);
        std::lock_guard lock(lock_);
        requestIdToDeviceIdMap_.erase(requestId);
        if (authOpenEventPromise != nullptr) {
            authOpenEventPromiseMap_.erase(requestId);
        }
    }
    return ret;
}

void AuthNegotiateChannel::StopCustomListening()
{
    DBinderSoftbusServer::GetInstance().AuthStopListening(AUTH_LINK_TYPE_RAW_ENHANCED_P2P);
}

void AuthNegotiateChannel::RemovePendingAuthReq(uint32_t authReqId)
{
    std::lock_guard lock(lock_);
    requestIdToDeviceIdMap_.erase(authReqId);
}

AuthHandle AuthNegotiateChannel::GetAuthHandle()
{
    return handle_;
}

void AuthNegotiateChannel::Register(const SyncDBACDataHook &syncDBACDataHook)
{
    syncDBACDataHook_ = syncDBACDataHook;
}

void AuthNegotiateChannel::SyncDBACData(const std::vector<uint8_t> &data)
{
    CONN_CHECK_AND_RETURN_LOGE(syncDBACDataHook_ != nullptr, CONN_WIFI_DIRECT, "syncDBACData not support");
    syncDBACDataHook_(data);
}
} // namespace OHOS::SoftBus
