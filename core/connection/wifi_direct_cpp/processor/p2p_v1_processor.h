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
#ifndef P2P_V1_PROCESSOR_H
#define P2P_V1_PROCESSOR_H

#include "common_timer_errors.h"
#include "timer.h"

#include "command/connect_command.h"
#include "command/disconnect_command.h"
#include "command/force_disconnect_command.h"
#include "command/negotiate_command.h"
#include "data/inner_link.h"
#include "entity/p2p_entity.h"
#include "processor/wifi_direct_processor.h"
#include "wifi_direct_executor.h"

namespace OHOS::SoftBus {
class P2pV1Processor : public WifiDirectProcessor {
public:
    explicit P2pV1Processor(const std::string &remoteDeviceId);
    ~P2pV1Processor() override;

    [[noreturn]] void Run() override;

    bool CanAcceptNegotiateDataAtState(WifiDirectCommand &command) override;
    void HandleCommandAfterTerminate(WifiDirectCommand &command) override;

private:
    static constexpr int P2P_VERSION = 2;

    static constexpr int P2P_V1_WAITING_RESPONSE_TIME_MS = 10000;
    static constexpr int P2P_V1_WAITING_REQUEST_TIME_MS = 10000;
    static constexpr int P2P_V1_WAITING_AUTH_TIME_MS = 10000;
    static constexpr int P2P_V1_WAITING_REUSE_RESPONSE_TIME_MS = 2000;
    static constexpr int DISCONNECT_WAIT_POST_REQUEST_MS = 450;
    static constexpr int TIMER_TIME = 200;

    struct TimeoutEvent { };

    static int ErrorCodeToV1ProtocolCode(int reason);
    static int ErrorCodeFromV1ProtocolCode(int reason);

    using ProcessorState = void (P2pV1Processor::*)();
    static std::string GetStateName(ProcessorState state);
    void SwitchState(ProcessorState state, int timeoutInMillis);
    void AvailableState();
    void WaitingReqResponseState();
    void WaitingClientJoiningState();
    void WaitAuthHandShakeState();
    void WaitingRequestState();
    void WaitingReuseResponseState();

    void ProcessConnectCommand(std::shared_ptr<ConnectCommand> &command);
    void ProcessDisconnectCommand(std::shared_ptr<DisconnectCommand> &command);
    void ProcessForceDisconnectCommand(std::shared_ptr<ForceDisconnectCommand> &command);

    void ProcessNegotiateCommandAtAvailableState(std::shared_ptr<NegotiateCommand> &command);
    void ProcessNegotiateCommandAtWaitingReqResponseState(std::shared_ptr<NegotiateCommand> &command);
    void ProcessNegotiateCommandAtWaitingRequestState(std::shared_ptr<NegotiateCommand> &command);
    void ProcessNegotiateCommandAtWaitingReuseResponseState(std::shared_ptr<NegotiateCommand> &command);
    void ProcessNegotiateCommandAtWaitingAuthHandShakeState(std::shared_ptr<NegotiateCommand> &command);
    void ProcessNegotiateCommandAtWaitingClientJoiningState(std::shared_ptr<NegotiateCommand> &command);
    int ProcessNegotiateCommandCommon(std::shared_ptr<NegotiateCommand> &command);

    void ProcessAuthConnEvent(std::shared_ptr<AuthOpenEvent> &event);
    void ProcessAuthExceptionEvent(const std::shared_ptr<AuthExceptionEvent> &event);

    void OnWaitReqResponseTimeoutEvent();
    void OnWaitReuseResponseTimeoutEvent();
    void OnWaitAuthHandShakeTimeoutEvent();
    void OnWaitRequestTimeoutEvent();
    int OnClientJoinEvent(std::shared_ptr<ClientJoinEvent> &event);

    int CreateLink();
    int CreateLinkAsNone();
    int CreateLinkAsGo();
    int CreateLinkAsGc();

    int ProcessConnectRequest(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectRequestAsGo(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole);
    int ProcessConnectRequestAsGc(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole);
    int ProcessNoAvailableInterface(std::shared_ptr<NegotiateCommand> &command, LinkInfo::LinkMode myRole);

    int ProcessConflictRequest(std::shared_ptr<NegotiateCommand> &command);

    int ProcessReuseRequest(std::shared_ptr<NegotiateCommand> &command);
    int ProcessReuseResponse(std::shared_ptr<NegotiateCommand> &command);
    int ProcessDisconnectRequest(std::shared_ptr<NegotiateCommand> &command);
    int ProcessForceDisconnectRequest(std::shared_ptr<NegotiateCommand> &command);

    int ProcessGetInterfaceInfoRequest(std::shared_ptr<NegotiateCommand> &command);

    int ProcessAuthHandShakeRequest(std::shared_ptr<NegotiateCommand> &command);

    static int SendConnectRequestAsNone(const NegotiateChannel &channel, WifiDirectRole expectedRole);
    static int SendConnectRequestAsGo(const NegotiateChannel &channel, const std::string &remoteMac);
    static int SendConnectResponseAsGo(const NegotiateChannel &channel, const std::string &remoteMac);
    static int SendConnectResponseAsNone(const NegotiateChannel &channel, const std::string &remoteMac);
    static int SendReuseRequest(const NegotiateChannel &channel);
    static int SendReuseResponse(const NegotiateChannel &channel, int32_t result);
    static int SendDisconnectRequest(const NegotiateChannel &channel);
    static int SendForceDisconnectRequest(const NegotiateChannel &channel);
    static int SendInterfaceInfoResponse(const NegotiateChannel &channel);
    static int SendNegotiateResult(const NegotiateChannel &channel, int32_t reason);
    static int SendHandShakeMessage(const NegotiateChannel &channel);

    int ProcessConnectResponseAtWaitingReqResponseState(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseAtWaitingClientJoiningState(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseAsGo(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseAsNone(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseWithGoInfoAsNone(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseWithGcInfoAsNone(std::shared_ptr<NegotiateCommand> &command);
    int ProcessConnectResponseAtWaitAuthHandShake(std::shared_ptr<NegotiateCommand> &command);

    int UpdateWhenConnectSuccess(std::string groupConfig, const NegotiateMessage &msg);
    int UpdateWhenCreateSuccess(const NegotiateMessage &msg);

    int CreateGroup(const NegotiateMessage &msg);
    int ConnectGroup(const NegotiateMessage &msg, const std::shared_ptr<NegotiateChannel> &channel);
    static bool IsNeedDhcp(const std::string &gcIp, const std::string &groupConfig);
    static int ChooseFrequency(int gcFreq, const std::vector<int> &gcChannels);
    int DestroyGroup();

    int ReuseP2p();
    int ReuseLink(const std::shared_ptr<ConnectCommand> &command, InnerLink &innerLink);
    std::string GetGoMac(LinkInfo::LinkMode role);

    int StartAuthListening(const std::string &localIp);
    int OpenAuthConnection(const NegotiateMessage &msg, const std::shared_ptr<NegotiateChannel> &channel);
    int RemoveLink(const std::string &remoteDeviceId);

    int GetFinalRoleWithPeerExpectedRole(WifiDirectRole myRole, WifiDirectRole peerRole, WifiDirectRole expectedRole,
        const std::string &localGoMac, const std::string &remoteGoMac);
    int GetFinalRoleAsGo(WifiDirectRole peerRole, WifiDirectRole expectedRole, const std::string &localGoMac,
        const std::string &remoteGoMac);
    int GetFinalRoleAsGc(WifiDirectRole peerRole, WifiDirectRole expectedRole, const std::string &localGoMac,
        const std::string &remoteGoMac);
    int GetFinalRoleAsNone(WifiDirectRole peerRole, WifiDirectRole expectedRole);
    int GenerateSinkLink(WifiDirectSinkLink &sinkLink);

    void CleanupIfNeed(int32_t ret, const std::string &remoteDeviceId);
    void Exclusive(const std::string &remoteDeviceId);
    void RemoveExclusive();

    void StartTimer(int timeoutInMillis);
    void StopTimer();
    
    std::string GetProcessorName() const override;
    std::string GetState() const override;
    [[noreturn]] void Terminate();

    ProcessorState state_;
    static std::map<std::string, ProcessorState> stateNameMapping;
    bool canAcceptNegotiateData_ = true;
    bool exclusive_ = false;

    std::shared_ptr<ConnectCommand> connectCommand_;
    std::string clientJoiningMac_;

    bool active_;
    bool hasRun_ = false;

    Utils::Timer timer_;
    uint32_t timerId_;
};
} // namespace OHOS::SoftBus
#endif
