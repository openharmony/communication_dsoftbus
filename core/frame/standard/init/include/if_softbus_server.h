/*
 * Copyright (c) 2021-2025 Huawei Device Co., Ltd.
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

#ifndef INTERFACES_INNERKITS_SOFTBUS_SERVER_H_
#define INTERFACES_INNERKITS_SOFTBUS_SERVER_H_

#include "ble_range.h"
#include "data_level.h"
#include "iremote_proxy.h"
#include "softbus_bus_center.h"
#include "softbus_connection.h"
#include "softbus_trans_def.h"

namespace OHOS {
class ISoftBusServer : public IRemoteBroker {
public:
    virtual ~ISoftBusServer() = default;

    virtual int32_t SoftbusRegisterService(const char *clientPkgName, const sptr<IRemoteObject> &object) = 0;
    virtual int32_t RegisterBrProxyService(const char *clientPkgName, const sptr<IRemoteObject>& object);

    virtual int32_t CreateSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp) = 0;
    virtual int32_t RemoveSessionServer(const char *pkgName, const char *sessionName, uint64_t timestamp) = 0;
    virtual int32_t OpenSession(const SessionParam *param, TransInfo *info) = 0;
    virtual int32_t OpenAuthSession(const char *sessionName, const ConnectionAddr *addrInfo) = 0;
    virtual int32_t NotifyAuthSuccess(int32_t channelId, int32_t channelType) = 0;
    virtual int32_t CloseChannel(const char *sessionName, int32_t channelId, int32_t channelType) = 0;
    virtual int32_t CloseChannelWithStatistics(int32_t channelId, int32_t channelType, uint64_t laneId,
        const void *dataInfo, uint32_t len) = 0;
    virtual int32_t ReleaseResources(int32_t channelId) = 0;
    virtual int32_t SendMessage(int32_t channelId, int32_t channelType,
        const void *data, uint32_t len, int32_t msgType) = 0;
    virtual int32_t JoinLNN(const char *pkgName, void *addr, uint32_t addrTypeLen, bool isForceJoin) = 0;
    virtual int32_t LeaveLNN(const char *pkgName, const char *networkId) = 0;
    virtual int32_t GetAllOnlineNodeInfo(const char *pkgName, void **info, uint32_t infoTypeLen, int *infoNum) = 0;
    virtual int32_t GetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen) = 0;
    virtual int32_t GetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
        uint32_t len) = 0;
    virtual int32_t SetNodeKeyInfo(const char *pkgName, const char *networkId, int key, unsigned char *buf,
        uint32_t len) = 0;
    virtual int32_t SetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag) = 0;
    virtual int32_t RegDataLevelChangeCb(const char *pkgName) = 0;
    virtual int32_t UnregDataLevelChangeCb(const char *pkgName) = 0;
    virtual int32_t SetDataLevel(const DataLevel *dataLevel) = 0;
    virtual int32_t StartTimeSync(const char *pkgName, const char *targetNetworkId, int32_t accuracy,
        int32_t period) = 0;
    virtual int32_t StopTimeSync(const char *pkgName, const char *targetNetworkId) = 0;
    virtual int32_t QosReport(int32_t channelId, int32_t chanType, int32_t appType, int32_t quality) = 0;
    virtual int32_t StreamStats(int32_t channelId, int32_t channelType, const StreamSendStats *data) = 0;
    virtual int32_t RippleStats(int32_t channelId, int32_t channelType, const TrafficStats *data) = 0;
    virtual int32_t GrantPermission(int uid, int pid, const char *sessionName);
    virtual int32_t RemovePermission(const char *sessionName);
    virtual int32_t PublishLNN(const char *pkgName, const PublishInfo *info);
    virtual int32_t StopPublishLNN(const char *pkgName, int32_t publishId);
    virtual int32_t RefreshLNN(const char *pkgName, const SubscribeInfo *info);
    virtual int32_t StopRefreshLNN(const char *pkgName, int32_t refreshId);
    virtual int32_t ActiveMetaNode(const MetaNodeConfigInfo *info, char *metaNodeId);
    virtual int32_t DeactiveMetaNode(const char *metaNodeId);
    virtual int32_t GetAllMetaNodeInfo(MetaNodeInfo *info, int32_t *infoNum);
    virtual int32_t ShiftLNNGear(const char *pkgName, const char *callerId, const char *targetNetworkId,
        const GearMode *mode);
    virtual int32_t TriggerRangeForMsdp(const char *pkgName, const RangeConfig *config);
    virtual int32_t StopRangeForMsdp(const char *pkgName, const RangeConfig *config);
    virtual int32_t RegisterRangeCallbackForMsdp(const char *pkgName) = 0;
    virtual int32_t UnregisterRangeCallbackForMsdp(const char *pkgName) = 0;
    virtual int32_t SyncTrustedRelationShip(const char *pkgName, const char *msg, uint32_t msgLen);
    virtual int32_t GetSoftbusSpecObject(sptr<IRemoteObject> &object);
    virtual int32_t GetBusCenterExObj(sptr<IRemoteObject> &object);
    virtual int32_t EvaluateQos(const char *peerNetworkId, TransDataType dataType, const QosTV *qos,
        uint32_t qosCount) = 0;
    virtual int32_t ProcessInnerEvent(int32_t eventType, uint8_t *buf, uint32_t len) = 0;
    virtual int32_t PrivilegeCloseChannel(uint64_t tokenId, int32_t pid, const char *peerNetworkId) = 0;
    virtual int32_t SetDisplayName(const char *pkgName, const char *nameData, uint32_t len);
    virtual int32_t CreateGroupOwner(const char *pkgName, const struct GroupOwnerConfig *config,
        struct GroupOwnerResult *result);
    virtual void DestroyGroupOwner(const char *pkgName);
    virtual int32_t CreateServer(const char *pkgName, const char *name);
    virtual int32_t RemoveServer(const char *pkgName, const char *name);
    virtual int32_t Connect(const char *pkgName, const char *name, const Address *address);
    virtual int32_t Disconnect(uint32_t handle);
    virtual int32_t Send(uint32_t handle, const uint8_t *data, uint32_t len);
    virtual int32_t ConnGetPeerDeviceId(uint32_t handle, char *deviceId, uint32_t len);

    virtual int32_t OpenBrProxy(const char *brMac, const char *uuid);
    virtual int32_t CloseBrProxy(int32_t channelId);
    virtual int32_t SendBrProxyData(int32_t channelId, char *data, uint32_t dataLen);
    virtual int32_t SetListenerState(int32_t channelId, int32_t type, bool CbEnabled);
    virtual bool IsProxyChannelEnabled(int32_t uid);
    virtual int32_t PushRegisterHook();
public:
    DECLARE_INTERFACE_DESCRIPTOR(u"OHOS.ISoftBusServer");
};
} // namespace OHOS

#endif // INTERFACES_INNERKITS_SOFTBUS_SERVER_H_