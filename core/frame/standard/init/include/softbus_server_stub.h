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

#ifndef SOFTBUS_SERVER_STUB_H_
#define SOFTBUS_SERVER_STUB_H_

#include <map>
#include "if_softbus_server.h"
#include "iremote_object.h"
#include "iremote_stub.h"
#include "bus_center_manager.h"

namespace OHOS {
class SoftBusServerStub : public IRemoteStub<ISoftBusServer> {
public:
    SoftBusServerStub();
    virtual ~SoftBusServerStub() = default;
    int32_t OnRemoteRequest(uint32_t code, MessageParcel &data, MessageParcel &reply, MessageOption &option) override;

private:
    int32_t GetNodeKeyInfoLen(int32_t key);
    int32_t SoftbusRegisterServiceInner(MessageParcel &data, MessageParcel &reply);

    int32_t CreateSessionServerInner(MessageParcel &data, MessageParcel &reply);
    int32_t RemoveSessionServerInner(MessageParcel &data, MessageParcel &reply);
    int32_t OpenSessionInner(MessageParcel &data, MessageParcel &reply);
    int32_t OpenAuthSessionInner(MessageParcel &data, MessageParcel &reply);
    int32_t NotifyAuthSuccessInner(MessageParcel &data, MessageParcel &reply);
    int32_t ReleaseResourcesInner(MessageParcel &data, MessageParcel &reply);
    int32_t CloseChannelInner(MessageParcel &data, MessageParcel &reply);
    int32_t CloseChannelWithStatisticsInner(MessageParcel &data, MessageParcel &reply);
    int32_t SendMessageInner(MessageParcel &data, MessageParcel &reply);
    int32_t CheckOpenSessionPermission(const SessionParam *param);
    int32_t CheckChannelPermission(int32_t channelId, int32_t channelType);
    int32_t EvaluateQosInner(MessageParcel &data, MessageParcel &reply);
    int32_t ProcessInnerEventInner(MessageParcel &data, MessageParcel &reply);
    int32_t PrivilegeCloseChannelInner(MessageParcel &data, MessageParcel &reply);

    int32_t JoinLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t LeaveLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetAllOnlineNodeInfoInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetLocalDeviceInfoInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetNodeKeyInfoInner(MessageParcel &data, MessageParcel &reply);
    int32_t SetNodeDataChangeFlagInner(MessageParcel &data, MessageParcel &reply);
    int32_t RegDataLevelChangeCbInner(MessageParcel &data, MessageParcel &reply);
    int32_t UnregDataLevelChangeCbInner(MessageParcel &data, MessageParcel &reply);
    int32_t SetDataLevelInner(MessageParcel &data, MessageParcel &reply);
    int32_t StartTimeSyncInner(MessageParcel &data, MessageParcel &reply);
    int32_t StopTimeSyncInner(MessageParcel &data, MessageParcel &reply);
    int32_t QosReportInner(MessageParcel &data, MessageParcel &reply);
    int32_t StreamStatsInner(MessageParcel &data, MessageParcel &reply);
    int32_t RippleStatsInner(MessageParcel &data, MessageParcel &reply);
    int32_t GrantPermissionInner(MessageParcel &data, MessageParcel &reply);
    int32_t RemovePermissionInner(MessageParcel &data, MessageParcel &reply);
    int32_t PublishLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t StopPublishLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t RefreshLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t StopRefreshLNNInner(MessageParcel &data, MessageParcel &reply);
    int32_t ActiveMetaNodeInner(MessageParcel &data, MessageParcel &reply);
    int32_t DeactiveMetaNodeInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetAllMetaNodeInfoInner(MessageParcel &data, MessageParcel &reply);
    int32_t ShiftLNNGearInner(MessageParcel &data, MessageParcel &reply);
    int32_t SyncTrustedRelationShipInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetSoftbusSpecObjectInner(MessageParcel &data, MessageParcel &reply);
    int32_t GetBusCenterExObjInner(MessageParcel &data, MessageParcel &reply);
    int32_t SetDisplayNameInner(MessageParcel &data, MessageParcel &reply);

    void InitMemberFuncMap();
    void InitMemberPermissionMap();

    using SoftbusServerStubFunc =
        int32_t (SoftBusServerStub::*)(MessageParcel &data, MessageParcel &reply);
    std::map<uint32_t, SoftbusServerStubFunc> memberFuncMap_;
    std::map<uint32_t, const char*> memberPermissionMap_;
};
} // namespace OHOS

#endif // SOFTBUS_SERVER_STUB_H_