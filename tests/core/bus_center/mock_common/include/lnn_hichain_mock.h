/*
 * Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef LNN_HICHAIN_MOCK_H
#define LNN_HICHAIN_MOCK_H

#include <gmock/gmock.h>
#include <map>
#include <mutex>

#include "device_auth.h"
#include "device_auth_defines.h"
#include "lnn_connection_fsm.h"
#include "softbus_adapter_thread.h"
#include "softbus_error_code.h"

#define TEST_LEN 1
#define TEST_SEQ 2

namespace OHOS {
class LnnHichainInterface {
public:
    LnnHichainInterface() {};
    virtual ~LnnHichainInterface() {};

    virtual int32_t InitDeviceAuthService() = 0;
    virtual void DestroyDeviceAuthService() = 0;
    virtual GroupAuthManager *GetGaInstance() = 0;
    virtual DeviceGroupManager *GetGmInstance() = 0;
    virtual void GetLnnTriggerInfo(LnnTriggerInfo *triggerInfo) = 0;
};

class LnnHichainInterfaceMock : public LnnHichainInterface {
public:
    LnnHichainInterfaceMock();
    ~LnnHichainInterfaceMock() override;
    MOCK_METHOD0(InitDeviceAuthService, int32_t());
    MOCK_METHOD0(DestroyDeviceAuthService, void());
    MOCK_METHOD0(GetGaInstance, GroupAuthManager *());
    MOCK_METHOD0(GetGmInstance, DeviceGroupManager *());
    MOCK_METHOD1(GetLnnTriggerInfo, void(LnnTriggerInfo *));

    static int32_t InvokeAuthDevice(
        int32_t osAccountId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *gaCallback);
    static int32_t InvokeDataChangeListener(const char *appId, const DataChangeListener *listener);
    static int32_t InvokeGetJoinedGroups1(
        int32_t osAccountId, const char *appId, int32_t groupType, char **returnGroupVec, uint32_t *groupNum);
    static int32_t InvokeGetJoinedGroups2(
        int32_t osAccountId, const char *appId, int32_t groupType, char **returnGroupVec, uint32_t *groupNum);
    static int32_t InvokeGetJoinedGroups3(
        int32_t osAccountId, const char *appId, int32_t groupType, char **returnGroupVec, uint32_t *groupNum);
    static int32_t ActionofunRegDataChangeListener(const char *appId);
    static int32_t ActionOfProcessData(
        int64_t authSeq, const uint8_t *data, uint32_t len, const DeviceAuthCallback *gaCallback);
    static int32_t AuthDeviceConnSend(
        int32_t osAccountId, int64_t authReqId, const char *authParams, const DeviceAuthCallback *gaCallback);
    static inline std::map<const char *, const DataChangeListener *> g_datachangelistener;
    static inline DeviceAuthCallback g_devAuthCb;
    static inline SoftBusCond cond;
    static inline SoftBusMutex mutex;
    static int32_t getRelatedGroups(
        int32_t accountId, const char *auth_appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum);
    static int32_t getRelatedGroups1(
        int32_t accountId, const char *auth_appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum);
    static int32_t getTrustedDevices(
        int32_t osAccountId, const char *appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum);
    static int32_t getTrustedDevices1(
        int32_t osAccountId, const char *appId, const char *groupId, char **returnDevInfoVec, uint32_t *deviceNum);
    static void destroyInfo(char **returnDevInfoVec);
};

} // namespace OHOS
#endif // AUTH_HICHAIN_MOCK_H