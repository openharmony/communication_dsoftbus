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


#ifndef INTERFACES_INNERKITS_FRAME_SERVER_PROXY_STANDARD_H_
#define INTERFACES_INNERKITS_FRAME_SERVER_PROXY_STANDARD_H_

#include "if_softbus_server.h"

namespace OHOS {
class SoftBusServerProxyFrame : public IRemoteProxy<ISoftBusServer> {
public:
    explicit SoftBusServerProxyFrame(const sptr<IRemoteObject> &impl)
        : IRemoteProxy<ISoftBusServer>(impl) {}
    virtual ~SoftBusServerProxyFrame() = default;

    int32_t SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object) override;
    int32_t RegisterBrProxyService(const char *clientPkgName, const sptr<IRemoteObject>& object) override;

    int32_t CreateSessionServer(const char *pkgName, const char *sessionName) override;
    int32_t RemoveSessionServer(const char *pkgName, const char *sessionName) override;
    int32_t OpenSession(const SessionParam *param, TransInfo *info) override;
    int32_t OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo) override;
    int32_t NotifyAuthSuccess(int32_t channelId, int32_t channelType) override;
    int32_t ReleaseResources(int32_t channelId) override;
    int32_t CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType) override;
    int32_t CloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId, const void *dataInfo,
        uint32_t len) override;
    int32_t SendMessage(int32_t channelId, int32_t channelType, const void *data,
        uint32_t len, int32_t msgType) override;

    int32_t JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen, bool isForceJoin) override;
    int32_t LeaveLNN(const char *pkgName, const char *networkId) override;
    int32_t GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum) override;
    int32_t GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen) override;
    int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
        uint32_t len) override;
    int32_t SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag) override;
    int32_t RegDataLevelChangeCb(const char *pkgName) override;
    int32_t UnregDataLevelChangeCb(const char *pkgName) override;
    int32_t SetDataLevel(const DataLevel *dataLevel) override;
    int32_t StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
        int32_t period) override;
    int32_t StopTimeSync(const char *pkgName, const char *targetNetworkId) override;
    int32_t QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality) override;
    int32_t StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data) override;
    int32_t RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data) override;
    int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
        uint32_t qosCount) override;
    int32_t ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len) override;
    int32_t PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId) override;
    int32_t RegisterRangeCallbackForMsdp(const char *pkgName) override;
    int32_t UnregisterRangeCallbackForMsdp(const char *pkgName) override;
private:
    static inline BrokerDelegator<SoftBusServerProxyFrame> delegator_;
    static sptr<IRemoteObject> clientCallbackStub_;
    static std::mutex instanceLock;

    static sptr<IRemoteObject> GetRemoteInstance();
};
} // namespace OHOS

#endif // !defined(INTERFACES_INNERKITS_FRAME_SERVER_PROXY_STANDARD_H_)
