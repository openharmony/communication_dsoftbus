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

#ifndef CLIENT_BUS_CENTER_MANAGER_MOCK_H
#define CLIENT_BUS_CENTER_MANAGER_MOCK_H

#include <gmock/gmock.h>
#include <securec.h>

#include "bus_center_server_proxy.h"
#include "softbus_adapter_thread.h"
#include "softbus_bus_center.h"
#include "softbus_config_type.h"
#include "softbus_feature_config.h"

namespace OHOS {
class ClientBusCenterManagerInterface {
public:
    ClientBusCenterManagerInterface() {};
    virtual ~ClientBusCenterManagerInterface() {};

    virtual int32_t BusCenterServerProxyInit(void);
    virtual void BusCenterServerProxyDeInit(void);
    virtual int32_t SoftbusGetConfig(ConfigType type, unsigned char *val, uint32_t len);
    virtual int32_t ServerIpcGetAllOnlineNodeInfo(
        const char *pkgName, void **info, uint32_t infoTypeLen, int32_t *infoNum);
    virtual int32_t ServerIpcGetLocalDeviceInfo(const char *pkgName, void *info, uint32_t infoTypeLen);
    virtual int32_t ServerIpcGetNodeKeyInfo(
        const char *pkgName, const char *networkId, int32_t key, unsigned char *buf, uint32_t len);
    virtual int32_t ServerIpcSetNodeDataChangeFlag(const char *pkgName, const char *networkId, uint16_t dataChangeFlag);
    virtual int32_t ServerIpcJoinLNN(const char *pkgName, void *addr, unsigned int addrTypeLen);
    virtual int32_t ServerIpcLeaveLNN(const char *pkgName, const char *networkId);
    virtual int32_t ServerIpcStartTimeSync(
        const char *pkgName, const char *targetNetworkId, int32_t accuracy, int32_t period);
    virtual int32_t ServerIpcStopTimeSync(const char *pkgName, const char *targetNetworkId);
    virtual int32_t ServerIpcPublishLNN(const char *pkgName, const PublishInfo *info);
    virtual int32_t ServerIpcStopPublishLNN(const char *pkgName, int32_t publishId);
    virtual int32_t ServerIpcRefreshLNN(const char *pkgName, const SubscribeInfo *info);
    virtual int32_t ServerIpcStopRefreshLNN(const char *pkgName, int32_t refreshId);
    virtual int32_t ServerIpcRegDataLevelChangeCb(const char *pkgName);
    virtual int32_t ServerIpcUnregDataLevelChangeCb(const char *pkgName);
    virtual int32_t ServerIpcSetDataLevel(const DataLevel *dataLevel);
    virtual int32_t SoftBusMutexLockInner(SoftBusMutex *mutex);
    virtual int32_t SoftBusMutexUnlockInner(SoftBusMutex *mutex);
};
class ClientBusCenterManagerInterfaceMock : public ClientBusCenterManagerInterface {
public:
    ClientBusCenterManagerInterfaceMock();
    ~ClientBusCenterManagerInterfaceMock() override;

    MOCK_METHOD0(BusCenterServerProxyInit, int32_t());
    MOCK_METHOD0(BusCenterServerProxyDeInit, void());
    MOCK_METHOD3(SoftbusGetConfig, int32_t(ConfigType, unsigned char *, uint32_t));
    MOCK_METHOD4(ServerIpcGetAllOnlineNodeInfo, int32_t(const char *, void **, uint32_t, int32_t *));
    MOCK_METHOD3(ServerIpcGetLocalDeviceInfo, int32_t(const char *, void *, uint32_t));
    MOCK_METHOD5(ServerIpcGetNodeKeyInfo, int32_t(const char *, const char *, int, unsigned char *, uint32_t));
    MOCK_METHOD3(ServerIpcSetNodeDataChangeFlag, int32_t(const char *, const char *, uint16_t));
    MOCK_METHOD3(ServerIpcJoinLNN, int32_t(const char *, void *, unsigned int));
    MOCK_METHOD2(ServerIpcLeaveLNN, int32_t(const char *, const char *));
    MOCK_METHOD4(ServerIpcStartTimeSync, int32_t(const char *, const char *, int32_t, int32_t));
    MOCK_METHOD2(ServerIpcStopTimeSync, int32_t(const char *, const char *));
    MOCK_METHOD2(ServerIpcPublishLNN, int32_t(const char *, const PublishInfo *));
    MOCK_METHOD2(ServerIpcStopPublishLNN, int32_t(const char *, int32_t));
    MOCK_METHOD2(ServerIpcRefreshLNN, int32_t(const char *, const SubscribeInfo *));
    MOCK_METHOD2(ServerIpcStopRefreshLNN, int32_t(const char *, int32_t));
    MOCK_METHOD1(ServerIpcRegDataLevelChangeCb, int32_t (const char *));
    MOCK_METHOD1(ServerIpcUnregDataLevelChangeCb, int32_t (const char *));
    MOCK_METHOD1(ServerIpcSetDataLevel, int32_t (const DataLevel *));
    MOCK_METHOD1(SoftBusMutexLockInner, int32_t (SoftBusMutex *));
    MOCK_METHOD1(SoftBusMutexUnlockInner, int32_t (SoftBusMutex *));
};
} // namespace OHOS
#endif // CLIENT_BUS_CENTER_MANAGER_MOCK_H
