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
#include "p2p_v1_processor.h"

#include <memory>
#include "securec.h"

#include "conn_log.h"
#include "softbus_adapter_timer.h"
#include "softbus_error_code.h"

#include "adapter/p2p_adapter.h"
#include "channel/auth_negotiate_channel.h"
#include "data/interface_manager.h"
#include "data/link_manager.h"
#include "dfx/wifi_direct_dfx.h"
#include "entity/p2p_entity.h"
#include "utils/wifi_direct_anonymous.h"
#include "utils/wifi_direct_utils.h"
#include "wifi_direct_scheduler_factory.h"
#include "wifi_direct_manager.h"
#include "wifi_direct_types.h"
#include "utils/wifi_direct_dfx.h"

namespace OHOS::SoftBus {
static constexpr int DECIMAL_BASE = 10;
static constexpr const char *PROCESSOR_NAME = "P2PV1Processor";
std::map<std::string, P2pV1Processor::ProcessorState> P2pV1Processor::stateNameMapping = {
    {"AvailableState",             &P2pV1Processor::AvailableState           },
    { "WaitingReqResponseState",   &P2pV1Processor::WaitingReqResponseState  },
    { "WaitingClientJoiningState", &P2pV1Processor::WaitingClientJoiningState},
    { "WaitingRequestState",       &P2pV1Processor::WaitingRequestState      },
    { "WaitingReuseResponseState", &P2pV1Processor::WaitingReuseResponseState},
    { "WaitAuthHandShakeState",    &P2pV1Processor::WaitAuthHandShakeState   },
    { "NullState",                 nullptr                                   }
};

// SoftBusErrNo to WifiDirectErrorCode
static std::map<int, int> p1ErrorMapping = {
    {SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE,                     V1_ERROR_IF_NOT_AVAILABLE                   },
    { SOFTBUS_CONN_PV1_BOTH_GO_ERR,                         V1_ERROR_BOTH_GO                            },
    { SOFTBUS_CONN_PV1_APPLY_GC_IP_FAIL,                    ERROR_P2P_APPLY_GC_IP_FAIL                  },
    { SOFTBUS_CONN_PV1_REUSE_FAIL,                          V1_ERROR_REUSE_FAILED                       },
    { SOFTBUS_CONN_PV1_CONNECT_GROUP_FAIL,                  V1_ERROR_CONNECT_GROUP_FAILED               },
    { SOFTBUS_CONN_PV1_BUSY_ERR,                            V1_ERROR_BUSY                               },
    { SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE, V1_ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE},
};

int P2pV1Processor::ErrorCodeToV1ProtocolCode(int reason)
{
    if (p1ErrorMapping.find(reason) != p1ErrorMapping.end()) {
        auto code = p1ErrorMapping[reason];
        if (code > V1_ERROR_END && code < V1_ERROR_START) {
            return code - V1_ERROR_START;
        }
        return code;
    }
    return reason;
}

int P2pV1Processor::ErrorCodeFromV1ProtocolCode(int reason)
{
    if (reason < 0 && reason > V1_ERROR_END - V1_ERROR_START) {
        auto code = reason + V1_ERROR_START;
        for (const auto it : p1ErrorMapping) {
            if (it.second == code) {
                return it.first;
            }
        }
        return code;
    }
    return reason;
}

P2pV1Processor::P2pV1Processor(const std::string &remoteDeviceId)
    : WifiDirectProcessor(remoteDeviceId), state_(&P2pV1Processor::AvailableState), timer_("P2pProcessor", TIMER_TIME),
    timerId_(Utils::TIMER_ERR_INVALID_VALUE)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
    timer_.Setup();
    active_ = false;
}

P2pV1Processor::~P2pV1Processor()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId_).c_str());
    StopTimer();
    timer_.Shutdown();
    RemoveExclusive();
    if (hasRun_) {
        WifiDirectUtils::SerialFlowExit();
    }
}

[[noreturn]] void P2pV1Processor::Run()
{
    WifiDirectUtils::SerialFlowEnter();
    hasRun_ = true;
    for (;;) {
        (this->*state_)();
    }
}

bool P2pV1Processor::CanAcceptNegotiateDataAtState(WifiDirectCommand &command)
{
    if (!canAcceptNegotiateData_) {
        return false;
    }

    auto nc = dynamic_cast<NegotiateCommand *>(&command);
    if (nc == nullptr) {
        return false;
    }
    return nc->GetNegotiateMessage().GetLegacyP2pCommandType() != LegacyCommandType::CMD_INVALID &&
        nc->GetNegotiateMessage().GetLegacyP2pCommandType() != LegacyCommandType::CMD_DISCONNECT_V1_REQ;
}

void P2pV1Processor::HandleCommandAfterTerminate(WifiDirectCommand &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "enter");
    auto nc = dynamic_cast<NegotiateCommand *>(&command);
    if (nc == nullptr) {
        return;
    }
    auto messageType = nc->GetNegotiateMessage().GetLegacyP2pCommandType();
    CONN_LOGI(CONN_WIFI_DIRECT, "messageType = %{public}d", messageType);
    std::set<LegacyCommandType> vaildMessageTypes = {
        LegacyCommandType::CMD_CONN_V1_REQ,
        LegacyCommandType::CMD_DISCONNECT_V1_REQ,
        LegacyCommandType::CMD_REUSE_REQ,
        LegacyCommandType::CMD_FORCE_DISCONNECT_V1_REQ,
    };
    if (vaildMessageTypes.find(messageType) == vaildMessageTypes.end()) {
        return;
    }
    WifiDirectSchedulerFactory::GetInstance().GetScheduler().QueueCommandFront(*nc);
}

void P2pV1Processor::SwitchState(ProcessorState state, int timeoutInMillis)
{
    StartTimer(timeoutInMillis);
    auto old = state_;
    state_ = state;
    CONN_LOGI(CONN_WIFI_DIRECT, "%{public}s => %{public}s", GetStateName(old).c_str(), GetStateName(state).c_str());
}

std::string P2pV1Processor::GetStateName(ProcessorState state)
{
    for (const auto &it : stateNameMapping) {
        if (it.second == state) {
            return it.first;
        }
    }
    return "UNKNOWN_STATE";
}

void P2pV1Processor::AvailableState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<ConnectCommand>>([this](std::shared_ptr<ConnectCommand> &command) {
            ProcessConnectCommand(command);
        })
        .Handle<std::shared_ptr<DisconnectCommand>>([this](std::shared_ptr<DisconnectCommand> &command) {
            ProcessDisconnectCommand(command);
        })
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtAvailableState(command);
        })
        .Handle<std::shared_ptr<ForceDisconnectCommand>>([this](std::shared_ptr<ForceDisconnectCommand> &command) {
            ProcessForceDisconnectCommand(command);
        });
}

void P2pV1Processor::WaitingReqResponseState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtWaitingReqResponseState(command);
        })
        .Handle<std::shared_ptr<TimeoutEvent>>([this](std::shared_ptr<TimeoutEvent> &event) {
            OnWaitReqResponseTimeoutEvent();
        })
        .Handle<std::shared_ptr<AuthExceptionEvent>>([this](std::shared_ptr<AuthExceptionEvent> &event) {
            ProcessAuthExceptionEvent(event);
        });
}

void P2pV1Processor::WaitingClientJoiningState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtWaitingClientJoiningState(command);
        })
        .Handle<std::shared_ptr<ClientJoinEvent>>([this](std::shared_ptr<ClientJoinEvent> &event) {
            auto ret = OnClientJoinEvent(event);
            CleanupIfNeed(ret, event->remoteDeviceId_);
            if (ret != SOFTBUS_OK) {
                if (connectCommand_ != nullptr) {
                    connectCommand_->OnFailure(ret);
                    connectCommand_ = nullptr;
                }
                Terminate();
            }
        });
}

void P2pV1Processor::WaitAuthHandShakeState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtWaitingAuthHandShakeState(command);
        })
        .Handle<std::shared_ptr<AuthOpenEvent>>([this](std::shared_ptr<AuthOpenEvent> &event) {
            ProcessAuthConnEvent(event);
        })
        .Handle<std::shared_ptr<TimeoutEvent>>([this](std::shared_ptr<TimeoutEvent> &event) {
            OnWaitAuthHandShakeTimeoutEvent();
        });
}

void P2pV1Processor::WaitingRequestState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtWaitingRequestState(command);
        })
        .Handle<std::shared_ptr<TimeoutEvent>>([this](std::shared_ptr<TimeoutEvent> &event) {
            OnWaitRequestTimeoutEvent();
        });
}

void P2pV1Processor::WaitingReuseResponseState()
{
    executor_->WaitEvent()
        .Handle<std::shared_ptr<NegotiateCommand>>([this](std::shared_ptr<NegotiateCommand> &command) {
            ProcessNegotiateCommandAtWaitingReuseResponseState(command);
        })
        .Handle<std::shared_ptr<TimeoutEvent>>([this](std::shared_ptr<TimeoutEvent> &event) {
            OnWaitReuseResponseTimeoutEvent();
        });
}

void P2pV1Processor::ProcessConnectCommand(std::shared_ptr<ConnectCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    connectCommand_ = command;
    active_ = true;
    Exclusive(connectCommand_->GetRemoteDeviceId());

    auto info = command->GetConnectInfo().info_;
    auto link = LinkManager::GetInstance().GetReuseLink(info.connectType, command->GetRemoteDeviceId());
    int ret = SOFTBUS_OK;
    if (link != nullptr) {
        uint32_t requestId = connectCommand_->GetConnectInfo().info_.requestId;
        WifiDirectDfx::GetInstance().SetReuseFlag(requestId);
        ret = ReuseLink(command, *link);
    } else {
        ret = CreateLink();
        CleanupIfNeed(ret, connectCommand_->GetRemoteDeviceId());
    }
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "connect failed, error=%{public}d", ret);
        command->OnFailure(ret);
        Terminate();
    }
}

static void RemoveLinkFromManager(const std::string &remoteDeviceId, int linkId, size_t &refCnt, std::string &remoteMac)
{
    LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::P2P, remoteDeviceId, [linkId, &refCnt, &remoteMac](InnerLink &link) {
            if (!link.IsContainId(linkId)) {
                return;
            }
            refCnt = link.GetReference();
            link.RemoveId(linkId);
            remoteMac = link.GetRemoteBaseMac();
        });
}

void P2pV1Processor::ProcessDisconnectCommand(std::shared_ptr<DisconnectCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    Exclusive(command->GetRemoteDeviceId());
    canAcceptNegotiateData_ = false;

    auto linkId = command->GetDisconnectInfo().info_.linkId;
    auto requestId = command->GetDisconnectInfo().info_.requestId;
    CONN_LOGI(CONN_WIFI_DIRECT, "disconnect device, linkId=%{public}d", linkId);
    std::string remoteMac;
    size_t refCnt = 0;
    RemoveLinkFromManager(command->GetRemoteDeviceId(), linkId, refCnt, remoteMac);
    if (refCnt == 0 || refCnt > 1) {
        CONN_LOGI(CONN_WIFI_DIRECT, "link is not exist or ref by others, refCnt=%{public}zu", refCnt);
        command->OnSuccess();
        Terminate();
    }
    auto ret = SendDisconnectRequest(*command->GetNegotiateChannel());
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "send disconnect request failed, error=%{public}d", ret);
        command->OnFailure(ret);
        Terminate();
    }

    int reuseCnt = 0;
    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&reuseCnt](const InterfaceInfo &interface) {
        reuseCnt = interface.GetReuseCount();
        return SOFTBUS_OK;
    });
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s, reuseCount=%{public}d", requestId,
        WifiDirectAnonymizeMac(remoteMac).c_str(), reuseCnt);
    if (reuseCnt == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount already 0");
        command->OnSuccess();
        Terminate();
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "wait for p2p auth to send data, DISCONNECT_WAIT_POST_REQUEST_MS=%{public}dms",
        DISCONNECT_WAIT_POST_REQUEST_MS);
    SoftBusSleepMs(DISCONNECT_WAIT_POST_REQUEST_MS);
    ret = RemoveLink(command->GetRemoteDeviceId());
    if (ret != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remove link failed, error=%{public}d", ret);
        command->OnFailure(ret);
        Terminate();
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "remove link success");
    command->OnSuccess();
    Terminate();
}

void P2pV1Processor::ProcessForceDisconnectCommand(std::shared_ptr<ForceDisconnectCommand> &command)
{
    Exclusive(command->GetRemoteDeviceId());
    canAcceptNegotiateData_ = false;
    auto info = command->GetDisconnectInfo();
    auto requestId = info.info_.requestId;
    CONN_LOGI(CONN_WIFI_DIRECT, "force disconnect device, requestId=%{public}d commandId=%{public}d", requestId,
        command->GetId());

    auto innerLink = LinkManager::GetInstance().GetReuseLink(info.info_.linkType, info.info_.remoteUuid);
    if (innerLink == nullptr) {
        CONN_LOGI(CONN_WIFI_DIRECT, "link is already not exist");
        command->OnSuccess();
        Terminate();
    }

    auto ret = SendForceDisconnectRequest(*command->GetNegotiateChannel());
    CONN_LOGE(CONN_WIFI_DIRECT, "send force disconnect request, ret=%{public}d", ret);
    if (ret == SOFTBUS_OK) {
        CONN_LOGI(
            CONN_WIFI_DIRECT, "wait for p2p auth to send data, sleep%{public}dms", DISCONNECT_WAIT_POST_REQUEST_MS);
        SoftBusSleepMs(DISCONNECT_WAIT_POST_REQUEST_MS);
    }

    LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::P2P, remoteDeviceId_);
    DestroyGroup();

    command->OnSuccess();
    Terminate();
}

void P2pV1Processor::ProcessNegotiateCommandAtAvailableState(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    Exclusive(command->GetRemoteDeviceId());

    bool reply = true;
    bool terminate = false;
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    int32_t ret = SOFTBUS_CONN_PV1_INTERNAL_ERR0R;
    switch (msgType) {
        case LegacyCommandType::CMD_CONN_V1_REQ:
            ret = ProcessConnectRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        case LegacyCommandType::CMD_REUSE_REQ:
            terminate = true;
            ret = ProcessReuseRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        case LegacyCommandType::CMD_DISCONNECT_V1_REQ:
            reply = false;
            terminate = true;
            canAcceptNegotiateData_ = false;
            ret = ProcessDisconnectRequest(command);
            break;
        case LegacyCommandType::CMD_FORCE_DISCONNECT_V1_REQ:
            reply = false;
            terminate = true;
            canAcceptNegotiateData_ = false;
            ret = ProcessForceDisconnectRequest(command);
            break;
        default:
            reply = false;
            terminate = true;
            ret = ProcessNegotiateCommandCommon(command);
            break;
    }

    if (ret != SOFTBUS_OK) {
        terminate = true;
        if (reply) {
            SendNegotiateResult(*command->GetNegotiateChannel(), ret);
        }
    }
    if (terminate) {
        Terminate();
    }
}

void P2pV1Processor::ProcessNegotiateCommandAtWaitingReqResponseState(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    int32_t ret = SOFTBUS_OK;
    switch (msgType) {
        case LegacyCommandType::CMD_CONN_V1_REQ:
            ret = ProcessConflictRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        case LegacyCommandType::CMD_CONN_V1_RESP:
            ret = ProcessConnectResponseAtWaitingReqResponseState(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        default:
            (void)ProcessNegotiateCommandCommon(command);
            break;
    }
    if (ret != SOFTBUS_OK) {
        connectCommand_->OnFailure(ret);
        connectCommand_ = nullptr;
        Terminate();
    }
}

void P2pV1Processor::ProcessNegotiateCommandAtWaitingRequestState(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    int32_t ret = SOFTBUS_OK;
    switch (msgType) {
        case LegacyCommandType::CMD_CONN_V1_REQ:
            StopTimer();
            ret = ProcessConnectRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        default:
            (void)ProcessNegotiateCommandCommon(command);
            break;
    }
    if (ret != SOFTBUS_OK) {
        SendNegotiateResult(*command->GetNegotiateChannel(), static_cast<WifiDirectErrorCode>(ret));
        Terminate();
    }
}

void P2pV1Processor::ProcessNegotiateCommandAtWaitingReuseResponseState(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    int32_t ret = SOFTBUS_OK;
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    switch (msgType) {
        case LegacyCommandType::CMD_REUSE_RESP:
            StopTimer();
            ret = ProcessReuseResponse(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        default:
            (void)ProcessNegotiateCommandCommon(command);
            break;
    }
    if (ret != SOFTBUS_OK) {
        connectCommand_->OnFailure(ret);
        connectCommand_ = nullptr;
        Terminate();
    }
}

void P2pV1Processor::ProcessNegotiateCommandAtWaitingAuthHandShakeState(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "commandId=%{public}u", command->GetId());
    int32_t ret = SOFTBUS_OK;
    bool terminate = false;
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    switch (msgType) {
        case LegacyCommandType::CMD_CTRL_CHL_HANDSHAKE:
            terminate = true;
            StopTimer();
            ret = ProcessAuthHandShakeRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        case LegacyCommandType::CMD_CONN_V1_RESP:
            ret = ProcessConnectResponseAtWaitAuthHandShake(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        case LegacyCommandType::CMD_REUSE_REQ:
            ret = ProcessReuseRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        default:
            (void)ProcessNegotiateCommandCommon(command);
            break;
    }
    if (ret != SOFTBUS_OK) {
        terminate = true;
        if (connectCommand_ != nullptr) {
            connectCommand_->OnFailure(ret);
            connectCommand_ = nullptr;
        }
    }
    if (ret == SOFTBUS_OK && terminate) {
        WifiDirectSinkLink sinkLink {};
        if (GenerateSinkLink(sinkLink) == SOFTBUS_OK) {
            GetWifiDirectManager()->notifyOnline(sinkLink.remoteMac, sinkLink.remoteIp, sinkLink.remoteUuid, active_);
            if (!active_) {
                GetWifiDirectManager()->notifyConnectedForSink(&sinkLink);
            }
        }
    }
    if (terminate) {
        Terminate();
    }
}

void P2pV1Processor::ProcessNegotiateCommandAtWaitingClientJoiningState(std::shared_ptr<NegotiateCommand> &command)
{
    int32_t ret = SOFTBUS_OK;
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    switch (msgType) {
        case LegacyCommandType::CMD_CTRL_CHL_HANDSHAKE:
            CONN_LOGW(CONN_WIFI_DIRECT, "receive auth handshake early, remoteDeviceId=%{public}s",
                WifiDirectAnonymizeDeviceId(command->GetRemoteDeviceId()).c_str());
            ret = ProcessAuthHandShakeRequest(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            P2pEntity::GetInstance().CancelNewClientJoining(clientJoiningMac_);
            Terminate();
        case LegacyCommandType::CMD_CONN_V1_RESP:
            ret = ProcessConnectResponseAtWaitingClientJoiningState(command);
            CleanupIfNeed(ret, command->GetRemoteDeviceId());
            break;
        default:
            (void)ProcessNegotiateCommandCommon(command);
            break;
    }
    if (ret != SOFTBUS_OK) {
        if (connectCommand_ != nullptr) {
            connectCommand_->OnFailure(ret);
            connectCommand_ = nullptr;
        }
        Terminate();
    }
}

int P2pV1Processor::ProcessNegotiateCommandCommon(std::shared_ptr<NegotiateCommand> &command)
{
    auto msgType = command->GetNegotiateMessage().GetLegacyP2pCommandType();
    switch (msgType) {
        case LegacyCommandType::CMD_PC_GET_INTERFACE_INFO_REQ:
            return ProcessGetInterfaceInfoRequest(command);
        default:
            CONN_LOGI(CONN_WIFI_DIRECT, "unexpected message type=%{public}d, current state=%{public}s",
                static_cast<int>(msgType), GetStateName(state_).c_str());
            return SOFTBUS_NOT_FIND;
    }
}

void P2pV1Processor::ProcessAuthConnEvent(std::shared_ptr<AuthOpenEvent> &event)
{
    StopTimer();
    if (event->reason_ != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "auth connect failed, error=%{public}d", event->reason_);
        Terminate();
    }
    auto channel = std::make_shared<AuthNegotiateChannel>(event->handle_);
    channel->SetClose();
    auto ret = SendHandShakeMessage(*channel);
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "send hand shake message failed, error=%{public}d", ret);
        Terminate();
    }
    LinkManager::GetInstance().ProcessIfPresent(InnerLink::LinkType::P2P, remoteDeviceId_, [&channel](InnerLink &link) {
        link.SetNegotiateChannel(channel);
    });

    CONN_LOGI(CONN_WIFI_DIRECT, "send hand shake message success");
    WifiDirectSinkLink sinkLink {};
    if (GenerateSinkLink(sinkLink) == SOFTBUS_OK) {
        GetWifiDirectManager()->notifyOnline(sinkLink.remoteMac, sinkLink.remoteIp, sinkLink.remoteUuid, active_);
        if (!active_) {
            GetWifiDirectManager()->notifyConnectedForSink(&sinkLink);
        }
    }
    Terminate();
}

void P2pV1Processor::ProcessAuthExceptionEvent(const std::shared_ptr<AuthExceptionEvent> &event)
{
    CONN_CHECK_AND_RETURN_LOGE(connectCommand_ != nullptr, CONN_WIFI_DIRECT, "connect command is nullptr");
    CONN_LOGE(CONN_WIFI_DIRECT, "AuthExceptionEvent error=%{public}d", event->error_);
    auto negotiateChannel = connectCommand_->GetConnectInfo().channel_;
    CONN_CHECK_AND_RETURN_LOGE(negotiateChannel != nullptr, CONN_WIFI_DIRECT, "auth negotiate channel is nullptr");
    auto authChannel = std::dynamic_pointer_cast<AuthNegotiateChannel>(negotiateChannel);
    CONN_CHECK_AND_RETURN_LOGE(authChannel != nullptr && *authChannel == event->handle_,
        CONN_WIFI_DIRECT, "other auth exception ignore");
    CleanupIfNeed(event->error_, connectCommand_->GetRemoteDeviceId());
    connectCommand_->OnFailure(static_cast<WifiDirectErrorCode>(event->error_));
    connectCommand_ = nullptr;
    Terminate();
}

void P2pV1Processor::OnWaitReqResponseTimeoutEvent()
{
    CONN_LOGE(CONN_WIFI_DIRECT, "wait connect response timeout");
    if (connectCommand_ != nullptr) {
        CleanupIfNeed(SOFTBUS_CONN_PV1_WAIT_CONNECT_RESPONSE_TIMEOUT, connectCommand_->GetRemoteDeviceId());
        connectCommand_->OnFailure(static_cast<WifiDirectErrorCode>(SOFTBUS_CONN_PV1_WAIT_CONNECT_RESPONSE_TIMEOUT));
        connectCommand_ = nullptr;
    }
    Terminate();
}

void P2pV1Processor::OnWaitReuseResponseTimeoutEvent()
{
    CONN_LOGE(CONN_WIFI_DIRECT, "wait reuse response timeout");
    if (connectCommand_ != nullptr) {
        connectCommand_->OnFailure(SOFTBUS_CONN_SOURCE_REUSE_LINK_FAILED);
        connectCommand_ = nullptr;
    }
    Terminate();
}

void P2pV1Processor::OnWaitAuthHandShakeTimeoutEvent()
{
    CONN_LOGE(CONN_WIFI_DIRECT, "wait auth hand shake timeout");
    if (connectCommand_ != nullptr) {
        connectCommand_->OnFailure(SOFTBUS_CONN_PV1_WAIT_AUTH_HANDSHAKE_TIMEOUT);
        connectCommand_ = nullptr;
    }
    Terminate();
}

void P2pV1Processor::OnWaitRequestTimeoutEvent()
{
    CONN_LOGE(CONN_WIFI_DIRECT, "wait request timeout");
    Terminate();
}

int P2pV1Processor::OnClientJoinEvent(std::shared_ptr<ClientJoinEvent> &event)
{
    CONN_CHECK_AND_RETURN_RET_LOGW(event->result_ == SOFTBUS_OK, event->result_, CONN_WIFI_DIRECT,
        "client join failed, error=%{public}d", event->result_);
    SwitchState(&P2pV1Processor::WaitAuthHandShakeState, P2P_V1_WAITING_AUTH_TIME_MS);
    return SOFTBUS_OK;
}

int P2pV1Processor::CreateLink()
{
    auto requestId = connectCommand_->GetConnectInfo().info_.requestId;
    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteDeviceId=%{public}s", requestId,
        WifiDirectAnonymizeDeviceId(connectCommand_->GetRemoteDeviceId()).c_str());

    if (connectCommand_->GetConnectInfo().info_.reuseOnly) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseOnly=true");
        return SOFTBUS_CONN_SOURCE_REUSE_LINK_FAILED;
    }

    auto role = LinkInfo::LinkMode::NONE;
    auto ret = InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::InterfaceType::P2P, [&role](InterfaceInfo &interface) {
            role = interface.GetRole();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get current p2p role failed, error=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", WifiDirectUtils::ToWifiDirectRole(role));
    switch (role) {
        case LinkInfo::LinkMode::NONE:
            return CreateLinkAsNone();
        case LinkInfo::LinkMode::GO:
            return CreateLinkAsGo();
        case LinkInfo::LinkMode::GC:
            return CreateLinkAsGc();
        default:
            return SOFTBUS_CONN_PV1_IF_ROLE_INVALID;
    }
}

int P2pV1Processor::CreateLinkAsNone()
{
    bool p2pEnable = false;
    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&p2pEnable](const InterfaceInfo &interface) {
        p2pEnable = interface.IsEnable();
        return SOFTBUS_OK;
    });
    if (!p2pEnable) {
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE");
        return SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE;
    }

    auto expectApiRole = connectCommand_->GetConnectInfo().info_.expectApiRole;
    WifiDirectRole expectedRole = WifiDirectRole::WIFI_DIRECT_ROLE_NONE;
    switch (expectApiRole) {
        case WIFI_DIRECT_API_ROLE_NONE:
            expectedRole = WifiDirectRole::WIFI_DIRECT_ROLE_NONE;
            break;
        case WIFI_DIRECT_API_ROLE_GO:
            expectedRole = WifiDirectRole::WIFI_DIRECT_ROLE_GO;
            break;
        case WIFI_DIRECT_API_ROLE_GC:
            expectedRole = WifiDirectRole::WIFI_DIRECT_ROLE_GC;
            break;
        case WIFI_DIRECT_API_ROLE_GO | WIFI_DIRECT_API_ROLE_GC:
            expectedRole = WifiDirectRole::WIFI_DIRECT_ROLE_AUTO;
            break;
        default:
            CONN_LOGE(CONN_WIFI_DIRECT, "illegal expected role, role=%{public}d", expectApiRole);
            return SOFTBUS_CONN_PV1_REQUEST_ROLE_INVALID;
    }

    connectCommand_->PreferNegotiateChannel();
    auto ret = SendConnectRequestAsNone(*connectCommand_->GetConnectInfo().channel_, expectedRole);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send message failed, error=%{public}d", ret);

    SwitchState(&P2pV1Processor::WaitingReqResponseState, P2P_V1_WAITING_RESPONSE_TIME_MS);
    return SOFTBUS_OK;
}

int P2pV1Processor::CreateLinkAsGo()
{
    auto ret = ReuseP2p();
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse p2p failed, error=%{public}d", ret);

    std::string localIp;
    std::string localMac;
    ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&localIp, &localMac](const InterfaceInfo &interface) {
            localIp = interface.GetIpString().ToIpString();
            localMac = interface.GetBaseMac();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get local ip failed, error=%{public}d", ret);

    auto remoteMac = std::string(connectCommand_->GetConnectInfo().info_.remoteMac);
    std::string gcIp;
    ret = P2pAdapter::RequestGcIp(remoteMac, gcIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "request gc ip failed, error=%{public}d", ret);
    auto success = LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P,
        connectCommand_->GetRemoteDeviceId(), [remoteMac, gcIp, localIp, localMac](InnerLink &link) {
            link.SetRemoteBaseMac(remoteMac);
            link.SetRemoteIpv4(gcIp);
            link.SetLocalBaseMac(localMac);
            link.SetLocalIpv4(localIp);
            link.SetState(InnerLink::LinkState::CONNECTING);
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "save remote ip failed");

    clientJoiningMac_ = remoteMac;
    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);

    connectCommand_->PreferNegotiateChannel();
    ret = SendConnectRequestAsGo(*connectCommand_->GetConnectInfo().channel_, remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send message failed, error=%{public}d", ret);
    SwitchState(&P2pV1Processor::WaitingClientJoiningState, 0);
    return SOFTBUS_OK;
}

int P2pV1Processor::CreateLinkAsGc()
{
    CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

int P2pV1Processor::ProcessConnectRequest(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto peerRole = msg.GetLegacyP2pRole();
    auto expectRole = msg.GetLegacyP2pExpectedRole();
    LinkInfo::LinkMode myRole = LinkInfo::LinkMode::NONE;
    bool p2pEnable = false;
    auto ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&myRole, &p2pEnable](const InterfaceInfo &interface) {
            myRole = interface.GetRole();
            p2pEnable = interface.IsEnable();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get role info failed, error=%{public}d", ret);

    if (myRole == LinkInfo::LinkMode::NONE && !p2pEnable) {
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE");
        return SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE;
    }

    auto remoteConfig = msg.GetLegacyP2pWifiConfigInfo();
    if (!remoteConfig.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteConfigSize=%{public}zu", remoteConfig.size());
        ret = P2pAdapter::SetPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "set wifi cfg failed, error=%{public}d", ret);
    }

    auto localGoMac = GetGoMac(myRole);
    auto remoteGoMac = msg.GetLegacyP2pGoMac();
    auto finalRole = GetFinalRoleWithPeerExpectedRole(
        WifiDirectUtils::ToWifiDirectRole(myRole), peerRole, expectRole, localGoMac, remoteGoMac);
    CONN_LOGI(CONN_WIFI_DIRECT, "finalRole=%{public}d", finalRole);
    if (finalRole == static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GO)) {
        return ProcessConnectRequestAsGo(command, myRole);
    } else if (finalRole == static_cast<int>(WifiDirectRole::WIFI_DIRECT_ROLE_GC)) {
        return ProcessConnectRequestAsGc(command, myRole);
    } else if (finalRole == static_cast<int>(SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE)) {
        return ProcessNoAvailableInterface(command, myRole);
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "finalRole invalid");
    return finalRole;
}

int P2pV1Processor::ProcessConnectRequestAsGo(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole)
{
    auto msg = command->GetNegotiateMessage();
    CONN_CHECK_AND_RETURN_RET_LOGW(msg.GetLegacyP2pContentType() == LegacyContentType::GC_INFO,
        SOFTBUS_CONN_PV1_BOTH_GO_ERR, CONN_WIFI_DIRECT, "content type not equal gc info");

    auto remoteMac = msg.GetLegacyP2pGcMac();
    if (myRole != LinkInfo::LinkMode::GO) {
        auto ret = CreateGroup(msg);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "create group failed, error=%{public}d", ret);
    } else {
        std::string remoteIp;
        auto ret = P2pAdapter::RequestGcIp(remoteMac, remoteIp);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "apply gc ip failed, error=%{public}d", ret);
        CONN_LOGI(CONN_WIFI_DIRECT, "apply gc ip %{public}s", WifiDirectAnonymizeIp(remoteIp).c_str());

        ret = ReuseP2p();
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse p2p failed, error=%{public}d", ret);

        std::string localMac;
        std::string localIp;
        ret = InterfaceManager::GetInstance().ReadInterface(
            InterfaceInfo::P2P, [&localMac, &localIp](const InterfaceInfo &interface) {
                localMac = interface.GetBaseMac();
                localIp = interface.GetIpString().ToIpString();
                return SOFTBUS_OK;
            });
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_CONN_PV1_REUSE_FAIL, CONN_WIFI_DIRECT,
            "update inner link failed, error=%{public}d", ret);
        auto success = LinkManager::GetInstance().ProcessIfAbsent(InnerLink::LinkType::P2P, msg.GetRemoteDeviceId(),
            [localMac, remoteMac, localIp, remoteIp](InnerLink &link) {
                link.SetLocalBaseMac(localMac);
                link.SetRemoteBaseMac(remoteMac);
                link.SetBeingUsedByRemote(true);
                link.SetLocalIpv4(localIp);
                link.SetRemoteIpv4(remoteIp);

                link.SetState(InnerLink::LinkState::CONNECTING);
            });
        CONN_CHECK_AND_RETURN_RET_LOGW(
            success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "update inner link failed");
    }

    clientJoiningMac_ = remoteMac;
    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    auto ret = SendConnectResponseAsGo(*command->GetNegotiateChannel(), remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send connection response failed, error=%{public}d", ret);

    SwitchState(&P2pV1Processor::WaitingClientJoiningState, -1);
    return SOFTBUS_OK;
}

int P2pV1Processor::SendConnectResponseAsGo(const NegotiateChannel &channel, const std::string &remoteMac)
{
    std::string selfWifiConfig;
    auto ret = P2pAdapter::GetSelfWifiConfigInfo(selfWifiConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get wifi cfg failed, error=%{public}d", ret);

    NegotiateMessage response;
    response.SetLegacyP2pVersion(P2P_VERSION);
    response.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_RESP);
    response.SetLegacyP2pContentType(LegacyContentType::GO_INFO);
    response.SetLegacyP2pGcMac(remoteMac);
    response.SetLegacyP2pWifiConfigInfo(selfWifiConfig);

    auto success = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [&response](InnerLink &link) {
        response.SetLegacyP2pGcIp(link.GetRemoteIpv4());
    });
    CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_NOT_FIND, CONN_WIFI_DIRECT, "link not found");

    ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&response](const InterfaceInfo &interface) {
            response.SetLegacyP2pMac(interface.GetBaseMac());
            response.SetLegacyP2pIp(interface.GetIpString().ToIpString());
            response.SetLegacyP2pGoIp(interface.GetIpString().ToIpString());
            response.SetLegacyP2pGoMac(interface.GetBaseMac());
            response.SetLegacyP2pGoPort(interface.GetP2pListenPort());
            response.SetLegacyP2pGroupConfig(interface.GetP2pGroupConfig());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build response failed, error=%{public}d", ret);
    return channel.SendMessage(response);
}

int P2pV1Processor::ProcessConnectRequestAsGc(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole)
{
    auto msg = command->GetNegotiateMessage();
    std::string localMac;
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&localMac](const InterfaceInfo &interface) {
            localMac = interface.GetBaseMac();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGE(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get local mac failed, error=%{public}d", ret);
    auto remoteMac = msg.GetLegacyP2pMac();
    auto contentType = msg.GetLegacyP2pContentType();
    CONN_LOGI(CONN_WIFI_DIRECT, "localMac=%{public}s, remoteMac=%{public}s, contentType=%{public}d",
        WifiDirectAnonymizeMac(localMac).c_str(), WifiDirectAnonymizeMac(remoteMac).c_str(),
        static_cast<int>(contentType));

    if (contentType == LegacyContentType::GC_INFO) {
        ret = SendConnectResponseAsNone(*command->GetNegotiateChannel(), remoteMac);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send message failed, error=%{public}d", ret);

        SwitchState(&P2pV1Processor::WaitingRequestState, P2P_V1_WAITING_REQUEST_TIME_MS);
        CONN_LOGD(CONN_WIFI_DIRECT, "send response with gc info success");
        return SOFTBUS_OK;
    }

    if (myRole == LinkInfo::LinkMode::GC) {
        ret = ReuseP2p();
        CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_REUSE_FAIL");
        ret = SendNegotiateResult(*command->GetNegotiateChannel(), SOFTBUS_OK);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send result message failed, error=%{public}d", ret);
        Terminate();
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "start connect group");
    ret = ConnectGroup(msg, command->GetNegotiateChannel());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "connect group failed, error=%{public}d", ret);
    ret = SendNegotiateResult(*command->GetNegotiateChannel(), SOFTBUS_OK);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send result message failed, error=%{public}d", ret);

    RemoveExclusive();
    SwitchState(&P2pV1Processor::WaitAuthHandShakeState, P2P_V1_WAITING_AUTH_TIME_MS);
    return SOFTBUS_OK;
}

int P2pV1Processor::SendConnectResponseAsNone(const NegotiateChannel &channel, const std::string &remoteMac)
{
    std::vector<int> channels;
    auto ret = P2pAdapter::GetChannel5GListIntArray(channels);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get 5g channels failed, error=%{public}d", ret);
    auto channelString = WifiDirectUtils::ChannelListToString(channels);

    std::string selfWifiConfig;
    ret = P2pAdapter::GetSelfWifiConfigInfo(selfWifiConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get wifi cfg failed, error=%{public}d", ret);

    NegotiateMessage response;
    response.SetLegacyP2pVersion(P2P_VERSION);
    response.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_RESP);
    response.SetLegacyP2pContentType(LegacyContentType::GC_INFO);
    response.SetLegacyP2pGcChannelList(channelString);
    response.SetLegacyP2pGoMac(remoteMac);
    response.SetLegacyP2pStationFrequency(P2pAdapter::GetStationFrequencyWithFilter());
    response.SetLegacyP2pWideBandSupported(P2pAdapter::IsWideBandSupported());
    response.SetLegacyP2pWifiConfigInfo(selfWifiConfig);

    ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&response](const InterfaceInfo &interface) {
            response.SetLegacyP2pMac(interface.GetBaseMac());
            response.SetLegacyP2pIp(interface.GetIpString().ToIpString());
            response.SetLegacyP2pGcMac(interface.GetBaseMac());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build response failed, error=%{public}d", ret);
    return channel.SendMessage(response);
}
int P2pV1Processor::SendInterfaceInfoResponse(const NegotiateChannel &channel)
{
    NegotiateMessage response;
    response.SetLegacyP2pCommandType(LegacyCommandType::CMD_PC_GET_INTERFACE_INFO_RESP);
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&response](const InterfaceInfo &interface) {
            response.SetLegacyP2pMac(interface.GetBaseMac());
            response.SetLegacyP2pGcIp(interface.GetIpString().ToIpString());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build response failed, error=%{public}d", ret);
    return channel.SendMessage(response);
}

int P2pV1Processor::SendNegotiateResult(const NegotiateChannel &channel, int reason)
{
    NegotiateMessage result;
    result.SetLegacyP2pVersion(P2P_VERSION);
    result.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_RESP);
    result.SetLegacyP2pContentType(LegacyContentType::RESULT);
    result.SetLegacyP2pResult(static_cast<LegacyResult>(ErrorCodeToV1ProtocolCode(reason)));

    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&result](const InterfaceInfo &interface) {
            result.SetLegacyP2pMac(interface.GetBaseMac());
            result.SetLegacyP2pIp(interface.GetIpString().ToIpString());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build result failed, error=%{public}d", ret);
    return channel.SendMessage(result);
}

int P2pV1Processor::SendReuseRequest(const NegotiateChannel &channel)
{
    NegotiateMessage result;
    result.SetLegacyP2pCommandType(LegacyCommandType::CMD_REUSE_REQ);
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&result](const InterfaceInfo &interface) {
            result.SetLegacyP2pMac(interface.GetBaseMac());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build result failed, error=%{public}d", ret);
    return channel.SendMessage(result);
}

int P2pV1Processor::SendReuseResponse(const NegotiateChannel &channel, int32_t result)
{
    NegotiateMessage response;
    response.SetLegacyP2pCommandType(LegacyCommandType::CMD_REUSE_RESP);
    response.SetLegacyP2pResult(static_cast<LegacyResult>(ErrorCodeToV1ProtocolCode(result)));

    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&response](const InterfaceInfo &interface) {
            response.SetLegacyP2pMac(interface.GetBaseMac());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build response failed, error=%{public}d", ret);
    return channel.SendMessage(response);
}

int P2pV1Processor::SendDisconnectRequest(const NegotiateChannel &channel)
{
    NegotiateMessage request;
    request.SetLegacyP2pCommandType(LegacyCommandType::CMD_DISCONNECT_V1_REQ);
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&request](const InterfaceInfo &interface) {
            request.SetLegacyP2pMac(interface.GetBaseMac());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build request failed, error=%{public}d", ret);
    return channel.SendMessage(request);
}

int P2pV1Processor::SendForceDisconnectRequest(const NegotiateChannel &channel)
{
    NegotiateMessage request;
    request.SetLegacyP2pCommandType(LegacyCommandType::CMD_FORCE_DISCONNECT_V1_REQ);
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&request](const InterfaceInfo &interface) {
            request.SetLegacyP2pMac(interface.GetBaseMac());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build request failed, error=%{public}d", ret);
    return channel.SendMessage(request);
}

int P2pV1Processor::ProcessNoAvailableInterface(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole)
{
    auto msg = command->GetNegotiateMessage();
    auto remoteDeviceId = command->GetRemoteDeviceId();
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());

    bool needFix = false;
    LinkManager::GetInstance().Dump();
    LinkManager::GetInstance().ForEach([remoteDeviceId, myRole, &needFix](InnerLink &link) {
        if (remoteDeviceId != link.GetRemoteDeviceId()) {
            return false;
        }
        if (myRole == LinkInfo::LinkMode::GC) {
            needFix = true;
            return true;
        }
        return false;
    });
    if (needFix) {
        CONN_LOGI(CONN_WIFI_DIRECT, "fix the obsolete link");
        (void)DestroyGroup();
        return SOFTBUS_CONN_PV1_LOCAL_DISCONNECTED_REMOTE_CONNECTED;
    }

    return SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR;
}

int P2pV1Processor::ProcessConflictRequest(std::shared_ptr<NegotiateCommand> &command)
{
    auto localMac = P2pAdapter::GetMacAddress();
    auto remoteMac = command->GetNegotiateMessage().GetLegacyP2pMac();

    CONN_LOGI(CONN_WIFI_DIRECT, "localMac=%{public}s, remoteMac=%{public}s", WifiDirectAnonymizeMac(localMac).c_str(),
        WifiDirectAnonymizeMac(remoteMac).c_str());
    auto reversal = WifiDirectUtils::CompareIgnoreCase(localMac, remoteMac) < 0;
    if (!reversal) {
        CONN_LOGI(CONN_WIFI_DIRECT, "no need reversal, ignore remote request");
        auto ret = SendNegotiateResult(*command->GetNegotiateChannel(), SOFTBUS_CONN_PV1_BUSY_ERR);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send result message failed, error=%{public}d", ret);
        return SOFTBUS_OK;
    }

    StopTimer();
    CONN_LOGI(CONN_WIFI_DIRECT, "need reversal, process remote request and retry local command");

    LinkInfo::LinkMode myRole = LinkInfo::LinkMode::NONE;
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&myRole](const InterfaceInfo &interface) {
            myRole = interface.GetRole();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get role failed, error=%{public}d", ret);
    if (myRole == LinkInfo::LinkMode::GO) {
        CONN_LOGI(CONN_WIFI_DIRECT, "decrease reuseCount and stop new client timer");
        RemoveLink(command->GetRemoteDeviceId());
        P2pEntity::GetInstance().CancelNewClientJoining(remoteMac);
        return SOFTBUS_OK;
    }
    executor_->SendEvent(command);
    CONN_LOGI(CONN_WIFI_DIRECT, "activeCommand=NULL");
    SwitchState(&P2pV1Processor::AvailableState, 0);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessReuseRequest(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto remoteMac = msg.GetLegacyP2pMac();
    int result = SOFTBUS_CONN_PV1_REUSE_FAIL;

    int ret = SOFTBUS_OK;
    bool success = false;

    auto oldLink =
        LinkManager::GetInstance().GetReuseLink(WIFI_DIRECT_CONNECT_TYPE_AUTH_NEGO_P2P, msg.GetRemoteDeviceId());
    if (oldLink == nullptr) {
        CONN_LOGE(CONN_WIFI_DIRECT, "link is null");
        goto Failed;
    }

    ret = ReuseP2p();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_REUSE_FAIL");
        goto Failed;
    }

    success = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [&](InnerLink &link) {
        link.SetBeingUsedByRemote(true);
    });
    if (!success) {
        CONN_LOGE(CONN_WIFI_DIRECT, "update inner link failed");
        goto Failed;
    }
    result = SOFTBUS_OK;

Failed:
    ret = SendReuseResponse(*command->GetNegotiateChannel(), result);
    CONN_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT,
        "send reuse response failed, remote=%{public}s, error=%{public}d", WifiDirectAnonymizeMac(remoteMac).c_str(),
        ret);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessReuseResponse(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto result = ErrorCodeFromV1ProtocolCode(static_cast<int32_t>(msg.GetLegacyP2pResult()));
    auto remoteMac = msg.GetLegacyP2pMac();

    CONN_LOGI(
        CONN_WIFI_DIRECT, "result=%{public}d, remoteMac=%{public}s", result, WifiDirectAnonymizeMac(remoteMac).c_str());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        result == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "remote response failed. result=%{public}d", result);

    auto ret = ReuseP2p();
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT,
            "local reuse failed, send disconnect to remote for decreasing reference, error=%{public}d", ret);
        SendDisconnectRequest(*command->GetNegotiateChannel());
        CONN_LOGI(CONN_WIFI_DIRECT,
            "wait for p2p auth to send data, DISCONNECT_WAIT_POST_REQUEST_MS=%{public}dms",
            DISCONNECT_WAIT_POST_REQUEST_MS);
        SoftBusSleepMs(DISCONNECT_WAIT_POST_REQUEST_MS);
        connectCommand_->OnFailure(ret);
        connectCommand_ = nullptr;
        Terminate();
    }

    auto requestId = connectCommand_->GetConnectInfo().info_.requestId;
    auto pid = connectCommand_->GetConnectInfo().info_.pid;
    WifiDirectLink dlink {};
    auto success = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [requestId, pid, &dlink](InnerLink &link) {
        link.GenerateLink(requestId, pid, dlink, true);
        dlink.channelId = WifiDirectUtils::FrequencyToChannel(link.GetFrequency());
    });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "update inner link failed");
    connectCommand_->OnSuccess(dlink);
    connectCommand_ = nullptr;
    Terminate();
}

int P2pV1Processor::ProcessDisconnectRequest(std::shared_ptr<NegotiateCommand> &command)
{
    int reuseCountOld = 0;
    auto ret =
        InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [&reuseCountOld](InterfaceInfo &interface) {
            reuseCountOld = interface.GetReuseCount();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get reuse count for interface info failed, error=%{public}d", ret);

    if (reuseCountOld <= 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCountOld already 0, do not call RemoveLink");
        return static_cast<int>(SOFTBUS_OK);
    }

    WifiDirectSinkLink sinkLink {};
    if (GenerateSinkLink(sinkLink) == SOFTBUS_OK) {
        GetWifiDirectManager()->notifyDisconnectedForSink(&sinkLink);
    }

    ret = RemoveLink(command->GetRemoteDeviceId());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "remove link failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessForceDisconnectRequest(std::shared_ptr<NegotiateCommand> &command)
{
    CONN_LOGI(CONN_WIFI_DIRECT, "process force disconnect request, remoteUuid=%{public}s",
        WifiDirectAnonymizeDeviceId(command->GetRemoteDeviceId()).c_str());
    LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::P2P, command->GetRemoteDeviceId());

    return DestroyGroup();
}

int P2pV1Processor::ProcessGetInterfaceInfoRequest(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto interfaceName = msg.GetLegacyInterfaceName();

    auto ret = SendInterfaceInfoResponse(*command->GetNegotiateChannel());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send interface info response failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessAuthHandShakeRequest(std::shared_ptr<NegotiateCommand> &command)
{
    auto channel = std::dynamic_pointer_cast<AuthNegotiateChannel>(command->GetNegotiateChannel());
    if (channel != nullptr) {
        channel->SetClose();
    }
    auto remoteDeviceId = command->GetRemoteDeviceId();

    WifiDirectLink dlink {};
    auto success = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::P2P, remoteDeviceId, [channel, this, &dlink](InnerLink &link) {
            link.SetState(InnerLink::LinkState::CONNECTED);
            link.SetNegotiateChannel(channel);
            if (connectCommand_ != nullptr) {
                link.GenerateLink(connectCommand_->GetConnectInfo().info_.requestId,
                    connectCommand_->GetConnectInfo().info_.pid, dlink, true);
                dlink.channelId = WifiDirectUtils::FrequencyToChannel(link.GetFrequency());
            }
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_NOT_FIND, CONN_WIFI_DIRECT,
        "update inner link failed, remoteDeviceId=%{public}s", WifiDirectAnonymizeDeviceId(remoteDeviceId).c_str());
    if (connectCommand_ != nullptr) {
        connectCommand_->OnSuccess(dlink);
        connectCommand_ = nullptr;
    }
    return SOFTBUS_OK;
}

int P2pV1Processor::SendConnectRequestAsNone(const NegotiateChannel &channel, WifiDirectRole expectedRole)
{
    std::vector<int> channels;
    int32_t ret = P2pAdapter::GetChannel5GListIntArray(channels);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get 5g channels failed, error=%{public}d", ret);
    auto channelString = WifiDirectUtils::ChannelListToString(channels);

    std::string selfWifiConfig;
    ret = P2pAdapter::GetSelfWifiConfigInfo(selfWifiConfig);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get self wifi cfg failed, error=%{public}d", ret);

    NegotiateMessage request;
    request.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    request.SetLegacyP2pVersion(P2P_VERSION);
    request.SetLegacyP2pContentType(LegacyContentType::GC_INFO);
    request.SetLegacyP2pBridgeSupport(false);
    request.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_NONE);
    request.SetLegacyP2pExpectedRole(expectedRole);
    request.SetLegacyP2pGoMac("");
    request.SetLegacyP2pGcChannelList(channelString);
    request.SetLegacyP2pStationFrequency(P2pAdapter::GetStationFrequencyWithFilter());
    request.SetLegacyP2pWideBandSupported(P2pAdapter::IsWideBandSupported());
    request.SetLegacyP2pWifiConfigInfo(selfWifiConfig);
    ret = InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&request](const InterfaceInfo &interface) {
        request.SetLegacyP2pMac(interface.GetBaseMac());
        request.SetLegacyP2pGcMac(interface.GetBaseMac());
        return SOFTBUS_OK;
    });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build request failed, error=%{public}d", ret);
    return channel.SendMessage(request);
}

int P2pV1Processor::SendConnectRequestAsGo(const NegotiateChannel &channel, const std::string &remoteMac)
{
    NegotiateMessage request;
    request.SetLegacyP2pVersion(P2P_VERSION);
    request.SetLegacyP2pCommandType(LegacyCommandType::CMD_CONN_V1_REQ);
    request.SetLegacyP2pContentType(LegacyContentType::GO_INFO);
    request.SetLegacyP2pRole(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
    request.SetLegacyP2pExpectedRole(WifiDirectRole::WIFI_DIRECT_ROLE_GO);
    request.SetLegacyP2pGcMac(remoteMac);
    request.SetLegacyP2pBridgeSupport(false);
    request.SetLegacyP2pWifiConfigInfo("");

    auto success = LinkManager::GetInstance().ProcessIfPresent(remoteMac, [&request](InnerLink &link) {
        request.SetLegacyP2pGcIp(link.GetRemoteIpv4());
    });
    CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_NOT_FIND, CONN_WIFI_DIRECT, "link not found");

    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&request](const InterfaceInfo &interface) {
            request.SetLegacyP2pMac(interface.GetBaseMac());
            request.SetLegacyP2pGroupConfig(interface.GetP2pGroupConfig());
            request.SetLegacyP2pGoMac(interface.GetBaseMac());
            request.SetLegacyP2pGoIp(interface.GetIpString().ToIpString());
            request.SetLegacyP2pGoPort(interface.GetP2pListenPort());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build request failed, error=%{public}d", ret);
    return channel.SendMessage(request);
}

int P2pV1Processor::SendHandShakeMessage(const NegotiateChannel &channel)
{
    NegotiateMessage message;
    message.SetLegacyP2pCommandType(LegacyCommandType::CMD_CTRL_CHL_HANDSHAKE);
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&message](const InterfaceInfo &interfce) {
            message.SetLegacyP2pMac(interfce.GetBaseMac());
            message.SetLegacyP2pIp(interfce.GetIpString().ToIpString());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "build message failed, error=%{public}d", ret);
    return channel.SendMessage(message);
}

int P2pV1Processor::ProcessConnectResponseAtWaitingReqResponseState(std::shared_ptr<NegotiateCommand> &command)
{
    StopTimer();
    LinkInfo::LinkMode myRole = LinkInfo::LinkMode::NONE;
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&myRole](const InterfaceInfo &interface) {
            myRole = interface.GetRole();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get role failed, error=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", WifiDirectUtils::ToWifiDirectRole(myRole));
    if (myRole == LinkInfo::LinkMode::NONE) {
        return ProcessConnectResponseAsNone(command);
    }
    CONN_LOGE(CONN_WIFI_DIRECT, "negotiate failed, my role invalid and changed during negotiation");
    return SOFTBUS_CONN_PV1_CONNECTED_WITH_MISMATCHED_ROLE_ERR;
}

int P2pV1Processor::ProcessConnectResponseAtWaitingClientJoiningState(std::shared_ptr<NegotiateCommand> &command)
{
    LinkInfo::LinkMode myRole = LinkInfo::LinkMode::NONE;
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&myRole](const InterfaceInfo &interface) {
            myRole = interface.GetRole();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get role failed, error=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "myRole=%{public}d", WifiDirectUtils::ToWifiDirectRole(myRole));
    if (myRole == LinkInfo::LinkMode::GO) {
        return ProcessConnectResponseAsGo(command);
    }
    CONN_LOGE(CONN_WIFI_DIRECT, "negotiate failed, my role invalid and changed during negotiation");
    return SOFTBUS_CONN_PV1_CONNECTED_WITH_MISMATCHED_ROLE_ERR;
}

int P2pV1Processor::ProcessConnectResponseAsGo(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto contentType = msg.GetLegacyP2pContentType();
    if (contentType != LegacyContentType::RESULT) {
        CONN_LOGE(CONN_WIFI_DIRECT, "content type not equal result type");
        return SOFTBUS_CONN_PV1_WRONG_NEGOTIATION_MSG_ERR;
    }

    auto remoteMac = msg.GetLegacyP2pMac();
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());

    auto result = ErrorCodeFromV1ProtocolCode(static_cast<int32_t>(msg.GetLegacyP2pResult()));
    CONN_CHECK_AND_RETURN_RET_LOGW(
        result == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "peer response error. result=%{public}d", result);

    auto requestId = connectCommand_->GetConnectInfo().info_.requestId;
    auto pid = connectCommand_->GetConnectInfo().info_.pid;
    bool alreadyAuthHandShake = false;
    WifiDirectLink dlink {};
    auto success = LinkManager::GetInstance().ProcessIfPresent(
        remoteMac, [msg, requestId, pid, &dlink, &alreadyAuthHandShake](InnerLink &link) {
            link.SetState(InnerLink::LinkState::CONNECTED);
            link.SetRemoteIpv4(msg.GetLegacyP2pIp());
            link.GenerateLink(requestId, pid, dlink, true);
            link.GetNegotiateChannel();
            dlink.channelId = WifiDirectUtils::FrequencyToChannel(link.GetFrequency());
            alreadyAuthHandShake = link.GetNegotiateChannel() != nullptr;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_NOT_FIND, CONN_WIFI_DIRECT, "update inner link failed");
    P2pEntity::GetInstance().CancelNewClientJoining(clientJoiningMac_);
    connectCommand_->OnSuccess(dlink);
    connectCommand_ = nullptr;

    RemoveExclusive();
    SwitchState(&P2pV1Processor::WaitAuthHandShakeState, P2P_V1_WAITING_AUTH_TIME_MS);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessConnectResponseAsNone(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto remoteConfig = msg.GetLegacyP2pWifiConfigInfo();
    if (!remoteConfig.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "remoteConfigSize=%{public}zu, remoteConfig=%{public}s", remoteConfig.size(),
            remoteConfig.c_str());
        int32_t ret = P2pAdapter::SetPeerWifiConfigInfo(remoteConfig);
        CONN_CHECK_AND_RETURN_RET_LOGW(
            ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "set wifi cfg failed, error=%{public}d", ret);
    }

    auto contentType = msg.GetLegacyP2pContentType();
    if (contentType == LegacyContentType::GO_INFO) {
        return ProcessConnectResponseWithGoInfoAsNone(command);
    }

    if (contentType == LegacyContentType::GC_INFO) {
        return ProcessConnectResponseWithGcInfoAsNone(command);
    }

    auto errorCode = ErrorCodeFromV1ProtocolCode(static_cast<int32_t>(msg.GetLegacyP2pResult()));
    CONN_LOGI(CONN_WIFI_DIRECT, "contentType=%{public}d, errorCode=%{public}d", contentType, errorCode);
    if (errorCode == SOFTBUS_OK) {
        // when content type is invalid and error code is OK
        return SOFTBUS_CONN_PV1_INTERNAL_ERR0R;
    }
    return errorCode;
}

int P2pV1Processor::ProcessConnectResponseWithGoInfoAsNone(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto ret = ConnectGroup(msg, command->GetNegotiateChannel());
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "connect group failed, error=%{public}d", ret);

    auto requestId = connectCommand_->GetConnectInfo().info_.requestId;
    auto pid = connectCommand_->GetConnectInfo().info_.pid;
    WifiDirectLink dlink {};
    auto success = LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::P2P, command->GetRemoteDeviceId(), [requestId, pid, &dlink](InnerLink &link) {
            link.GenerateLink(requestId, pid, dlink, true);
            dlink.channelId = WifiDirectUtils::FrequencyToChannel(link.GetFrequency());
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "update inner link failed");
    connectCommand_->OnSuccess(dlink);
    connectCommand_ = nullptr;

    RemoveExclusive();
    SwitchState(&P2pV1Processor::WaitAuthHandShakeState, P2P_V1_WAITING_AUTH_TIME_MS);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessConnectResponseWithGcInfoAsNone(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto ret = CreateGroup(msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "create group failed, error=%{public}d", ret);
    std::string remoteMac = msg.GetLegacyP2pMac();
    ret = SendConnectRequestAsGo(*command->GetNegotiateChannel(), remoteMac);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "send message failed, error=%{public}d", ret);

    SwitchState(&P2pV1Processor::WaitingClientJoiningState, -1);
    return SOFTBUS_OK;
}

int P2pV1Processor::ProcessConnectResponseAtWaitAuthHandShake(std::shared_ptr<NegotiateCommand> &command)
{
    auto msg = command->GetNegotiateMessage();
    auto remoteMac = msg.GetLegacyP2pMac();
    CONN_LOGI(CONN_WIFI_DIRECT, "remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());

    auto contentType = msg.GetLegacyP2pContentType();
    if (contentType != LegacyContentType::RESULT) {
        CONN_LOGE(CONN_WIFI_DIRECT, "content type not equal result type");
        return SOFTBUS_CONN_PV1_WRONG_NEGOTIATION_MSG_ERR;
    }

    auto result = ErrorCodeFromV1ProtocolCode(static_cast<int32_t>(msg.GetLegacyP2pResult()));
    CONN_CHECK_AND_RETURN_RET_LOGW(
        result == SOFTBUS_OK, result, CONN_WIFI_DIRECT, "peer response error. result=%{public}d", result);

    if (connectCommand_ != nullptr) {
        auto requestId = connectCommand_->GetConnectInfo().info_.requestId;
        auto pid = connectCommand_->GetConnectInfo().info_.pid;
        WifiDirectLink dlink {};
        auto success = LinkManager::GetInstance().ProcessIfPresent(
            remoteMac, [msg, requestId, pid, &dlink](InnerLink &link) {
                link.SetState(InnerLink::LinkState::CONNECTED);
                link.GenerateLink(requestId, pid, dlink, true);
                dlink.channelId = WifiDirectUtils::FrequencyToChannel(link.GetFrequency());
            });
        CONN_CHECK_AND_RETURN_RET_LOGW(success, SOFTBUS_NOT_FIND, CONN_WIFI_DIRECT,
            "link not found, remoteMac=%{public}s", WifiDirectAnonymizeMac(remoteMac).c_str());
        connectCommand_->OnSuccess(dlink);
        connectCommand_ = nullptr;
    }
    return SOFTBUS_OK;
}

int P2pV1Processor::UpdateWhenCreateSuccess(const NegotiateMessage &msg)
{
    std::string remoteMac = msg.GetLegacyP2pMac();
    std::string remoteIp;
    int32_t ret = P2pAdapter::RequestGcIp(remoteMac, remoteIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, SOFTBUS_CONN_PV1_APPLY_GC_IP_FAIL, CONN_WIFI_DIRECT,
        "apply gc ip failed, error=%{public}d", ret);

    std::string localMac;
    std::string localIp;
    ret = InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [&localMac, &localIp](InterfaceInfo &interface) {
            localMac = interface.GetBaseMac();
            localIp = interface.GetIpString().ToIpString();
            interface.SetReuseCount(interface.GetReuseCount() + 1);
            CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", interface.GetReuseCount());
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "update interface failed, error=%{public}d", ret);

    auto success = LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::P2P, msg.GetRemoteDeviceId(), [localMac, localIp, remoteMac, remoteIp](InnerLink &link) {
            link.SetLocalBaseMac(localMac);
            link.SetLocalIpv4(localIp);
            link.SetRemoteBaseMac(remoteMac);
            link.SetRemoteIpv4(remoteIp);
            link.SetState(InnerLink::LinkState::CONNECTING);
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "update inner link failed");

    clientJoiningMac_ = remoteMac;
    P2pEntity::GetInstance().NotifyNewClientJoining(remoteMac);
    return StartAuthListening(localIp);
}

int P2pV1Processor::CreateGroup(const NegotiateMessage &msg)
{
    auto isRemoteWideBandSupported = msg.GetLegacyP2pWideBandSupported();
    auto stationFrequency = msg.GetLegacyP2pStationFrequency();
    auto channelListString = msg.GetLegacyP2pGcChannelList();
    auto finalFrequency = ChooseFrequency(stationFrequency, WifiDirectUtils::StringToChannelList(channelListString));
    CONN_CHECK_AND_RETURN_RET_LOGW(finalFrequency > 0, finalFrequency, CONN_WIFI_DIRECT,
        "choose frequency failed, frequency=%{public}d", finalFrequency);
    int coexCode = P2pAdapter::GetCoexConflictCode(IF_NAME_P2P, WifiDirectUtils::FrequencyToChannel(finalFrequency));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        coexCode == SOFTBUS_OK, coexCode, CONN_WIFI_DIRECT, "coex conflict, errorcode=%{public}d", coexCode);
    bool isLocalWideBandSupported = P2pAdapter::IsWideBandSupported();
    CONN_LOGI(CONN_WIFI_DIRECT,
        "stationFrequency=%{public}d, finalFrequency=%{public}d, "
        "localWideBand=%{public}d, remoteWideBand=%{public}d",
        stationFrequency, finalFrequency, isLocalWideBandSupported, isRemoteWideBandSupported);

    P2pAdapter::CreateGroupParam param {};
    param.frequency = finalFrequency;
    param.isWideBandSupported = isLocalWideBandSupported && isRemoteWideBandSupported;
    auto result = P2pEntity::GetInstance().CreateGroup(param);
    if (connectCommand_ != nullptr) {
        connectCommand_->GetConnectInfo().info_.dfxInfo.frequency = param.frequency;
    }
    CONN_CHECK_AND_RETURN_RET_LOGW(result.errorCode_ == SOFTBUS_OK, result.errorCode_, CONN_WIFI_DIRECT,
        "create group failed, error=%{public}d", result.errorCode_);
    return UpdateWhenCreateSuccess(msg);
}

int P2pV1Processor::UpdateWhenConnectSuccess(std::string groupConfig, const NegotiateMessage &msg)
{
    std::string localMac;
    std::string localIp;
    auto myRole = LinkInfo::LinkMode::NONE;
    auto ret = InterfaceManager::GetInstance().UpdateInterface(
        InterfaceInfo::P2P, [groupConfig, &myRole, &localMac, &localIp](InterfaceInfo &interface) {
            interface.SetP2pGroupConfig(groupConfig);
            int32_t reuseCount = interface.GetReuseCount();
            interface.SetReuseCount(reuseCount + 1);
            CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", interface.GetReuseCount());
            localMac = interface.GetBaseMac();
            localIp = interface.GetIpString().ToIpString();
            myRole = interface.GetRole();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "update interface failed, error=%{public}d", ret);
    std::string remoteMac = msg.GetLegacyP2pMac();
    std::string remoteIp = msg.GetLegacyP2pGoIp();
    auto success = LinkManager::GetInstance().ProcessIfAbsent(
        InnerLink::LinkType::P2P, msg.GetRemoteDeviceId(), [localMac, localIp, remoteMac, remoteIp](InnerLink &link) {
            link.SetRemoteBaseMac(remoteMac);
            link.SetLocalBaseMac(localMac);
            link.SetRemoteIpv4(remoteIp);
            link.SetLocalIpv4(localIp);
            link.SetState(InnerLink::LinkState::CONNECTED);
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        success, SOFTBUS_CONN_PV1_INTERNAL_ERR0R, CONN_WIFI_DIRECT, "update inner link failed");
    WifiDirectUtils::SyncLnnInfoForP2p(WifiDirectUtils::ToWifiDirectRole(myRole), localMac, msg.GetLegacyP2pGoMac());
    ret = StartAuthListening(localIp);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "start auth listen failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

int P2pV1Processor::ConnectGroup(const NegotiateMessage &msg, const std::shared_ptr<NegotiateChannel> &channel)
{
    auto goPort = msg.GetLegacyP2pGoPort();
    auto groupConfig = msg.GetLegacyP2pGroupConfig();
    auto gcIp = msg.GetLegacyP2pGcIp();
    CONN_LOGI(CONN_WIFI_DIRECT, "goPort=%{public}d, gcIp=%{public}s", goPort, WifiDirectAnonymizeIp(gcIp).c_str());
    std::vector<std::string> configs = WifiDirectUtils::SplitString(groupConfig, "\n");
    if (configs.size() < P2P_GROUP_CONFIG_INDEX_FREQ) {
        CONN_LOGI(CONN_WIFI_DIRECT, "wifi config spilt size is invaild param");
        return SOFTBUS_INVALID_PARAM;
    }
    auto freq = strtol(configs[P2P_GROUP_CONFIG_INDEX_FREQ].c_str(), nullptr, DECIMAL_BASE);
    int coexCode = P2pAdapter::GetCoexConflictCode(IF_NAME_P2P, WifiDirectUtils::FrequencyToChannel(freq));
    CONN_CHECK_AND_RETURN_RET_LOGE(
        coexCode == SOFTBUS_OK, coexCode, CONN_WIFI_DIRECT, "coex conflict, errorcode=%{public}d", coexCode);
    P2pAdapter::ConnectParam params {};
    params.isNeedDhcp = IsNeedDhcp(gcIp, groupConfig);
    params.groupConfig = groupConfig;
    params.gcIp = gcIp;
    params.goIp = msg.GetLegacyP2pGoIp();
    auto result = P2pEntity::GetInstance().Connect(params);
    if (result.errorCode_ != SOFTBUS_OK) {
        CONN_LOGI(CONN_WIFI_DIRECT, "connect group failed, error=%{public}d", result.errorCode_);
        P2pEntity::GetInstance().Disconnect(P2pAdapter::DestroyGroupParam { IF_NAME_P2P });
        return result.errorCode_;
    }
    auto ret = UpdateWhenConnectSuccess(groupConfig, msg);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "update date failed, error=%{public}d", ret);
    ret = OpenAuthConnection(msg, channel);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "open auth connection failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

bool P2pV1Processor::IsNeedDhcp(const std::string &gcIp, const std::string &groupConfig)
{
    if (gcIp.empty()) {
        CONN_LOGI(CONN_WIFI_DIRECT, "gcIp is empty, DHCP is true");
        return true;
    }

    auto configs = WifiDirectUtils::SplitString(groupConfig, "\n");
    if (configs.size() == P2P_GROUP_CONFIG_INDEX_MAX && configs[P2P_GROUP_CONFIG_INDEX_MODE] == "1") {
        CONN_LOGI(CONN_WIFI_DIRECT, "DHCP is true");
        return true;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "DHCP is false");
    return false;
}

int P2pV1Processor::ChooseFrequency(int gcFreq, const std::vector<int> &gcChannels)
{
    auto goFreq = P2pAdapter::GetStationFrequencyWithFilter();
    CONN_LOGI(CONN_WIFI_DIRECT, "goFreq=%{public}d, gcFreq=%{public}d", goFreq, gcFreq);

    if (goFreq != CHANNEL_INVALID || gcFreq != CHANNEL_INVALID) {
        int32_t recommendChannel = P2pAdapter::GetRecommendChannel();
        if (recommendChannel != CHANNEL_INVALID) {
            CONN_LOGI(CONN_WIFI_DIRECT, "recommendChannel=%{public}d", recommendChannel);
            return WifiDirectUtils::ChannelToFrequency(recommendChannel);
        }
    }

    std::vector<int> goChannels;
    int32_t ret = P2pAdapter::GetChannel5GListIntArray(goChannels);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get local Channels list failed, error=%{public}d", ret);

    for (auto goChannel : goChannels) {
        if (std::find(gcChannels.begin(), gcChannels.end(), goChannel) != gcChannels.end()) {
            return WifiDirectUtils::ChannelToFrequency(goChannel);
        }
    }

    if (WifiDirectUtils::Is2GBand(goFreq)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use goFreq=%{public}d", goFreq);
        return goFreq;
    }
    if (WifiDirectUtils::Is2GBand(gcFreq)) {
        CONN_LOGI(CONN_WIFI_DIRECT, "use gcFreq=%{public}d", gcFreq);
        return gcFreq;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "use 2G_FIRST=%{public}d", FREQUENCY_2G_FIRST);
    return FREQUENCY_2G_FIRST;
}

int P2pV1Processor::DestroyGroup()
{
    CONN_LOGI(CONN_WIFI_DIRECT, "start to destroy group");
    P2pAdapter::DestroyGroupParam param { IF_NAME_P2P };
    auto result = P2pEntity::GetInstance().DestroyGroup(param);
    CONN_CHECK_AND_RETURN_RET_LOGW(result.errorCode_ == SOFTBUS_OK, result.errorCode_, CONN_WIFI_DIRECT,
        "destroy group failed, error=%{public}d", result.errorCode_);
    return SOFTBUS_OK;
}

int P2pV1Processor::ReuseP2p()
{
    auto ret = P2pEntity::GetInstance().ReuseLink();
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "reuse link failed, error=%{public}d", ret);
    return InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [](InterfaceInfo &interface) {
        auto reuseCnt = interface.GetReuseCount();
        interface.SetReuseCount(reuseCnt + 1);
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", interface.GetReuseCount());
        return SOFTBUS_OK;
    });
}

int P2pV1Processor::ReuseLink(const std::shared_ptr<ConnectCommand> &command, InnerLink &link)
{
    auto requestId = command->GetConnectInfo().info_.requestId;
    auto pid = command->GetConnectInfo().info_.pid;
    bool isBeingUsedByLocal = link.IsBeingUsedByLocal();
    CONN_LOGI(CONN_WIFI_DIRECT, "isBeingUsedByLocal=%{public}d", isBeingUsedByLocal);
    if (isBeingUsedByLocal) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuse success");
        WifiDirectLink dlink {};
        link.GenerateLink(requestId, pid, dlink, true);
        command->OnSuccess(dlink);
        Terminate();
        return SOFTBUS_OK;
    }

    CONN_LOGI(CONN_WIFI_DIRECT, "requestId=%{public}d, remoteMac=%{public}s", requestId,
        WifiDirectAnonymizeMac(command->GetConnectInfo().info_.remoteMac).c_str());
    auto ipv4Info = link.GetRemoteIpv4();
    CONN_CHECK_AND_RETURN_RET_LOGW(!ipv4Info.empty(), SOFTBUS_CONN_PV1_USED_BY_OTHER_SERVICE_ERR, CONN_WIFI_DIRECT,
        "p2p link is used by another service");

    command->PreferNegotiateChannel();
    auto ret = SendReuseRequest(*command->GetConnectInfo().channel_);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "post request failed, error=%{public}d", ret);
    SwitchState(&P2pV1Processor::WaitingReuseResponseState, P2P_V1_WAITING_REUSE_RESPONSE_TIME_MS);
    return SOFTBUS_OK;
}

std::string P2pV1Processor::GetGoMac(LinkInfo::LinkMode myRole)
{
    if (myRole == LinkInfo::LinkMode::NONE) {
        return "";
    }

    std::string goMac;
    if (myRole == LinkInfo::LinkMode::GO) {
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&goMac](const InterfaceInfo &interface) {
            goMac = interface.GetBaseMac();
            return SOFTBUS_OK;
        });
        return goMac;
    }
    LinkManager::GetInstance().ForEach([&goMac](InnerLink &link) {
        if (link.GetLinkType() == InnerLink::LinkType::P2P) {
            goMac = link.GetRemoteBaseMac();
            return true;
        }
        return false;
    });
    return goMac;
}

int P2pV1Processor::StartAuthListening(const std::string &localIp)
{
    int port = 0;
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&port](const InterfaceInfo &interface) {
            port = interface.GetP2pListenPort();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get go port failed, error=%{public}d", ret);
    if (port > 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "already has started listening, port=%{public}d", port);
        return SOFTBUS_OK;
    }

    auto pair = AuthNegotiateChannel::StartListening(AUTH_LINK_TYPE_P2P, localIp, 0);
    CONN_CHECK_AND_RETURN_RET_LOGW(pair.first > 0, pair.first, CONN_WIFI_DIRECT, "start listen failed");
    ret = InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [&pair](InterfaceInfo &interface) {
        interface.SetP2pListenPort(pair.first);
        interface.SetP2pListenModule(pair.second);
        return SOFTBUS_OK;
    });
    if (ret != SOFTBUS_OK) {
        CONN_LOGE(CONN_WIFI_DIRECT, "update interface failed, error=%{public}d", ret);
        AuthNegotiateChannel::StopListening(AUTH_LINK_TYPE_P2P, pair.second);
    }
    return ret;
}

int P2pV1Processor::OpenAuthConnection(const NegotiateMessage &msg, const std::shared_ptr<NegotiateChannel> &channel)
{
    AuthNegotiateChannel::OpenParam param {};
    param.type = AUTH_LINK_TYPE_P2P;
    param.remoteUuid = msg.GetRemoteDeviceId();
    param.remoteIp = msg.GetLegacyP2pGoIp();
    param.remotePort = msg.GetLegacyP2pGoPort();
    auto ret =
        InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&param](const InterfaceInfo &interface) {
            int module = interface.GetP2pListenModule();
            param.module = static_cast<ListenerModule>(module);
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get listen module failed, error=%{public}d", ret);

    auto authChannel = std::dynamic_pointer_cast<AuthNegotiateChannel>(channel);
    uint32_t authReqId = 0;
    ret = AuthNegotiateChannel::OpenConnection(param, authChannel, authReqId);
    CONN_CHECK_AND_RETURN_RET_LOGW(
        ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "open p2p auth failed, error=%{public}d", ret);
    return SOFTBUS_OK;
}

int P2pV1Processor::RemoveLink(const std::string &remoteDeviceId)
{
    P2pEntity::GetInstance().CancelNewClientJoining(clientJoiningMac_);
    int reuseCount = 0;
    auto ret = InterfaceManager::GetInstance().ReadInterface(
        InterfaceInfo::P2P, [&reuseCount](const InterfaceInfo &interface) {
            reuseCount = interface.GetReuseCount();
            return SOFTBUS_OK;
        });
    CONN_CHECK_AND_RETURN_RET_LOGW(ret == SOFTBUS_OK, ret, CONN_WIFI_DIRECT, "get port failed, error=%{public}d", ret);

    CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", reuseCount);
    if (reuseCount == 0) {
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount already 0, do not call entity disconnect");
        return SOFTBUS_OK;
    }
    P2pAdapter::DestroyGroupParam param { IF_NAME_P2P };
    auto result = P2pEntity::GetInstance().Disconnect(param);
    CONN_CHECK_AND_RETURN_RET_LOGW(result.errorCode_ == SOFTBUS_OK, result.errorCode_, CONN_WIFI_DIRECT,
        "entity disconnect failed, error=%{public}d", result.errorCode_);

    return InterfaceManager::GetInstance().UpdateInterface(InterfaceInfo::P2P, [](InterfaceInfo &interface) {
        auto reuseCount = interface.GetReuseCount();
        if (reuseCount == 0) {
            CONN_LOGW(CONN_WIFI_DIRECT, "reuseCount already 0 and can not be reduced");
            return SOFTBUS_OK;
        }
        interface.SetReuseCount(reuseCount - 1);
        CONN_LOGI(CONN_WIFI_DIRECT, "reuseCount=%{public}d", interface.GetReuseCount());
        return SOFTBUS_OK;
    });
}

int P2pV1Processor::GetFinalRoleWithPeerExpectedRole(WifiDirectRole myRole, WifiDirectRole peerRole,
    WifiDirectRole expectedRole, const std::string &localGoMac, const std::string &remoteGoMac)
{
    CONN_LOGI(CONN_WIFI_DIRECT,
        "myRole=%{public}d, peerRole=%{public}d, expectedRole=%{public}d, localGoMac=%{public}s, "
        "remoteGoMac=%{public}s",
        static_cast<int>(myRole), static_cast<int>(peerRole), static_cast<int>(expectedRole),
        WifiDirectAnonymizeMac(localGoMac).c_str(), WifiDirectAnonymizeMac(remoteGoMac).c_str());

    if (myRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
        return GetFinalRoleAsGo(peerRole, expectedRole, localGoMac, remoteGoMac);
    } else if (myRole == WifiDirectRole::WIFI_DIRECT_ROLE_GC) {
        return GetFinalRoleAsGc(peerRole, expectedRole, localGoMac, remoteGoMac);
    } else if (myRole == WifiDirectRole::WIFI_DIRECT_ROLE_NONE) {
        return GetFinalRoleAsNone(peerRole, expectedRole);
    } else {
        CONN_LOGE(CONN_WIFI_DIRECT, "myRole invalid. myRole=%{public}d", static_cast<int>(myRole));
        return SOFTBUS_INVALID_PARAM;
    }
}

int P2pV1Processor::GetFinalRoleAsGo(
    WifiDirectRole peerRole, WifiDirectRole expectedRole, const std::string &localGoMac, const std::string &remoteGoMac)
{
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_BOTH_GO_ERR");
        return SOFTBUS_CONN_PV1_BOTH_GO_ERR;
    }
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_GC) {
        if (remoteGoMac.empty() || WifiDirectUtils::CompareIgnoreCase(remoteGoMac, localGoMac) != 0) {
            return SOFTBUS_CONN_PV1_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
        }
        if (expectedRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
            CONN_LOGE(CONN_WIFI_DIRECT, "mismatched role, remote expect GO");
            return SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR;
        }
        return WifiDirectRole::WIFI_DIRECT_ROLE_GO;
    }
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_NONE) {
        if (expectedRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
            CONN_LOGE(CONN_WIFI_DIRECT, "mismatched role, remote expect GO");
            return SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR;
        }
        return WifiDirectRole::WIFI_DIRECT_ROLE_GO;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "peer role invalid. peerRole=%{public}d ", static_cast<int>(peerRole));
    return SOFTBUS_CONN_PV1_PEER_ROLE_INVALID;
}

int P2pV1Processor::GetFinalRoleAsGc(
    WifiDirectRole peerRole, WifiDirectRole expectedRole, const std::string &localGoMac, const std::string &remoteGoMac)
{
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
        if (!localGoMac.empty() && WifiDirectUtils::CompareIgnoreCase(localGoMac, remoteGoMac) == 0) {
            return WifiDirectRole::WIFI_DIRECT_ROLE_GC;
        }
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE");
        return SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE;
    }
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_NONE) {
        CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE");
        return SOFTBUS_CONN_PV1_IF_NOT_AVAILABLE;
    }
    CONN_LOGE(CONN_WIFI_DIRECT, "SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE");
    return SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE;
}

int P2pV1Processor::GetFinalRoleAsNone(WifiDirectRole peerRole, WifiDirectRole expectedRole)
{
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
        if (expectedRole == WifiDirectRole::WIFI_DIRECT_ROLE_GC) {
            CONN_LOGE(CONN_WIFI_DIRECT, "mismatched role, peerRole=%{public}d, expectRole=%{public}d",
                static_cast<int>(peerRole), static_cast<int>(expectedRole));
            return SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR;
        }
        return WifiDirectRole::WIFI_DIRECT_ROLE_GC;
    }
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_GC) {
        if (expectedRole == WifiDirectRole::WIFI_DIRECT_ROLE_GO) {
            CONN_LOGE(CONN_WIFI_DIRECT, "mismatched role, remote expect GO");
            return SOFTBUS_CONN_PV1_GC_AVAILABLE_WITH_MISMATCHED_ROLE_ERR;
        }
        return SOFTBUS_CONN_PV1_GC_CONNECTED_TO_ANOTHER_DEVICE;
    }
    if (peerRole == WifiDirectRole::WIFI_DIRECT_ROLE_NONE) {
        if (expectedRole == WifiDirectRole::WIFI_DIRECT_ROLE_GC) {
            return WifiDirectRole::WIFI_DIRECT_ROLE_GO;
        }
        return WifiDirectRole::WIFI_DIRECT_ROLE_GC;
    }

    CONN_LOGE(CONN_WIFI_DIRECT, "peer role invalid. peerRole=%{public}d ", static_cast<int>(peerRole));
    return SOFTBUS_INVALID_PARAM;
}

int P2pV1Processor::GenerateSinkLink(WifiDirectSinkLink &sinkLink)
{
    bool cpyRet = strcpy_s(sinkLink.remoteUuid, sizeof(sinkLink.remoteUuid), remoteDeviceId_.c_str()) == EOK;
    CONN_CHECK_AND_RETURN_RET_LOGW(cpyRet, SOFTBUS_STRCPY_ERR, CONN_WIFI_DIRECT, "strcpy failed");

    InterfaceManager::GetInstance().ReadInterface(InterfaceInfo::P2P, [&sinkLink](const InterfaceInfo &interface) {
        sinkLink.bandWidth = static_cast<WifiDirectBandWidth>(interface.GetBandWidth());
        sinkLink.channelId = WifiDirectUtils::FrequencyToChannel(interface.GetCenter20M());
        return SOFTBUS_OK;
    });
    sinkLink.linkType = WIFI_DIRECT_LINK_TYPE_P2P;
    LinkManager::GetInstance().ProcessIfPresent(
        InnerLink::LinkType::P2P, remoteDeviceId_, [&sinkLink, &cpyRet](InnerLink &link) {
            cpyRet = cpyRet &&
                (strcpy_s(sinkLink.localIp, sizeof(sinkLink.localIp), link.GetLocalIpv4().c_str()) == EOK) &&
                (strcpy_s(sinkLink.remoteIp, sizeof(sinkLink.remoteIp), link.GetRemoteIpv4().c_str()) == EOK) &&
                (strcpy_s(sinkLink.remoteMac, sizeof(sinkLink.remoteMac), link.GetRemoteBaseMac().c_str()) == EOK);
        });

    CONN_CHECK_AND_RETURN_RET_LOGW(cpyRet, SOFTBUS_STRCPY_ERR, CONN_WIFI_DIRECT, "strcpy failed");
    return SOFTBUS_OK;
}

void P2pV1Processor::CleanupIfNeed(int32_t reason, const std::string &remoteDeviceId)
{
    if (reason == SOFTBUS_OK) {
        return;
    }

    bool exist =
        LinkManager::GetInstance().ProcessIfPresent(InnerLink::LinkType::P2P, remoteDeviceId, [](InnerLink &link) {});
    if (!exist) {
        return;
    }
    CONN_LOGI(CONN_WIFI_DIRECT, "start cleanup ctx, reason=%{public}d", reason);
    (void)RemoveLink(remoteDeviceId);
    LinkManager::GetInstance().RemoveLink(InnerLink::LinkType::P2P, remoteDeviceId);
}

void P2pV1Processor::Exclusive(const std::string &remoteDeviceId)
{
    if (exclusive_) {
        CONN_LOGE(CONN_WIFI_DIRECT, "already exclusive, skip");
        return;
    }
    InterfaceManager::GetInstance().LockInterface(InterfaceInfo::P2P, remoteDeviceId);
    exclusive_ = true;
}

void P2pV1Processor::RemoveExclusive()
{
    if (!exclusive_) {
        return;
    }
    InterfaceManager::GetInstance().UnlockInterface(InterfaceInfo::P2P);
    exclusive_ = false;
}

void P2pV1Processor::StartTimer(int timeoutInMillis)
{
    StopTimer();
    if (timeoutInMillis <= 0) {
        return;
    }

    timerId_ = timer_.Register(
        [this]() {
            CONN_LOGE(CONN_WIFI_DIRECT, "timeout");
            executor_->SendEvent(std::make_shared<TimeoutEvent>());
        },
        timeoutInMillis, true);
    CONN_LOGD(CONN_WIFI_DIRECT, "timerId=%{public}u", timerId_);
}

void P2pV1Processor::StopTimer()
{
    if (timerId_ != Utils::TIMER_ERR_INVALID_VALUE) {
        CONN_LOGD(CONN_WIFI_DIRECT, "timerId=%{public}u", timerId_);
        timer_.Unregister(timerId_);
        timerId_ = Utils::TIMER_ERR_INVALID_VALUE;
    }
}

void P2pV1Processor::Terminate()
{
    StopTimer();
    RemoveExclusive();
    throw ProcessorTerminate();
}

std::string P2pV1Processor::GetProcessorName() const
{
    return PROCESSOR_NAME;
}

std::string P2pV1Processor::GetState() const
{
    return GetStateName(state_);
}
} // namespace OHOS::SoftBus
