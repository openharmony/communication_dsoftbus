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

#ifndef LNN_NET_LEDGER_MOCK_H
#define LNN_NET_LEDGER_MOCK_H

#include <gmock/gmock.h>
#include <mutex>

#include "bus_center_manager.h"
#include "lnn_node_info.h"
#include "lnn_distributed_net_ledger.h"
#include "bus_center_info_key.h"
#include "lnn_device_info.h"
#include "softbus_bus_center.h"
#include "bus_center_event.h"

namespace OHOS {
class LnnNetLedgerInterface {
public:
    LnnNetLedgerInterface() {};
    virtual ~LnnNetLedgerInterface() {};
    virtual int32_t LnnGetLocalStrInfo(InfoKey key, char *info, uint32_t len) = 0;
    virtual const NodeInfo *LnnGetLocalNodeInfo(void) = 0;
    virtual int32_t LnnGetAuthPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetSessionPort(const NodeInfo *info) = 0;
    virtual int32_t LnnGetProxyPort(const NodeInfo *info) = 0;
    virtual const char *LnnGetBtMac(const NodeInfo *info) = 0;
    virtual const char *LnnGetDeviceName(const DeviceBasicInfo *info) = 0;
    virtual char *LnnConvertIdToDeviceType(uint16_t typeId) = 0;
    virtual int32_t LnnGetP2pRole(const NodeInfo *info) = 0;
    virtual const char *LnnGetP2pMac(const NodeInfo *info) = 0;
    virtual uint64_t LnnGetSupportedProtocols(const NodeInfo *info) = 0;
    virtual int32_t LnnConvertDeviceTypeToId(const char *deviceType, uint16_t *typeId) = 0;
    virtual int32_t LnnGetLocalNumInfo(InfoKey key, int32_t *info) = 0;
    virtual int32_t LnnSetNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnClearNetCapability(uint32_t *capability, NetCapability type) = 0;
    virtual int32_t LnnSetLocalNumInfo(InfoKey key, int32_t info) = 0;
    virtual int32_t LnnSetLocalStrInfo(InfoKey key, const char *info) = 0;
    virtual int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
        char *dstIdBuf, uint32_t dstIdBufLen) = 0;
    virtual bool LnnSetDLDeviceInfoName(const char *udid, const char *name) = 0;
    virtual bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info) = 0;
    virtual int32_t LnnSetP2pRole(NodeInfo *info, int32_t role) = 0;
    virtual int32_t LnnSetP2pMac(NodeInfo *info, const char *p2pMac) = 0;
    virtual int32_t LnnSetP2pGoMac(NodeInfo *info, const char *goMac) = 0;
    virtual int32_t LnnGetAllOnlineAndMetaNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual int32_t LnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum) = 0;
    virtual NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type) = 0;
};
class LnnNetLedgertInterfaceMock : public LnnNetLedgerInterface {
public:
    LnnNetLedgertInterfaceMock();
    ~LnnNetLedgertInterfaceMock() override;
    MOCK_METHOD3(LnnGetLocalStrInfo, int32_t (InfoKey, char *, uint32_t));
    MOCK_METHOD0(LnnGetLocalNodeInfo, const NodeInfo *());
    MOCK_METHOD1(LnnGetAuthPort, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetSessionPort, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetProxyPort, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetBtMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetDeviceName, const char *(const DeviceBasicInfo *));
    MOCK_METHOD1(LnnConvertIdToDeviceType, char *(uint16_t));
    MOCK_METHOD1(LnnGetP2pRole, int32_t (const NodeInfo *));
    MOCK_METHOD1(LnnGetP2pMac, const char *(const NodeInfo *));
    MOCK_METHOD1(LnnGetSupportedProtocols, uint64_t (const NodeInfo *));
    MOCK_METHOD2(LnnConvertDeviceTypeToId, int32_t (const char *, uint16_t *));
    MOCK_METHOD2(LnnGetLocalNumInfo, int32_t (InfoKey, int32_t *));
    MOCK_METHOD2(LnnSetNetCapability, int32_t (uint32_t *, NetCapability));
    MOCK_METHOD2(LnnClearNetCapability, int32_t (uint32_t *, NetCapability));
    MOCK_METHOD2(LnnSetLocalNumInfo, int32_t (InfoKey, int32_t));
    MOCK_METHOD2(LnnSetLocalStrInfo, int32_t (InfoKey, const char *));
    MOCK_METHOD5(LnnConvertDlId, int32_t (const char *, IdCategory, IdCategory, char *, uint32_t));
    MOCK_METHOD2(LnnSetDLDeviceInfoName, bool (const char *, const char *));
    MOCK_METHOD2(LnnSetDLP2pInfo, bool (const char *, const P2pInfo *));
    MOCK_METHOD2(LnnSetP2pRole, int32_t (NodeInfo *, int32_t));
    MOCK_METHOD2(LnnSetP2pMac, int32_t (NodeInfo *, const char *));
    MOCK_METHOD2(LnnSetP2pGoMac, int32_t (NodeInfo *, const char *));
    MOCK_METHOD2(LnnGetAllOnlineAndMetaNodeInfo, int32_t (NodeBasicInfo **, int32_t *));
    MOCK_METHOD2(LnnGetAllOnlineNodeInfo, int32_t (NodeBasicInfo **info, int32_t *infoNum));
    MOCK_METHOD2(LnnGetNodeInfoById, NodeInfo *(const char *id, IdCategory type));
    static int32_t ActionOfLnnGetAllOnline(NodeBasicInfo **info, int32_t *infoNum);
    static int32_t ActionOfLnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
        char *dstIdBuf, uint32_t dstIdBufLen);
    static inline std::map<LnnEventType, LnnEventHandler> g_lnnevent_handlers;
    static int32_t ActionOfLnnGetAllOnlineNodeInfo(NodeBasicInfo **info, int32_t *infoNum);
};
} // namespace OHOS
#endif // LNN_NET_LEDGER_MOCK_H