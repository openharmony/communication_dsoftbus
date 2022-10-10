/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef LNN_DISTRIBUTED_NET_LEDGER_H
#define LNN_DISTRIBUTED_NET_LEDGER_H

#include <pthread.h>
#include <stdint.h>

#include "bus_center_info_key.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define INT_TO_STR_SIZE 12
#define INVALID_CONNECTION_CODE_VALUE -1
#define SHORT_UDID_HASH_LEN 8
typedef struct {
    InfoKey key;
    int32_t (*getInfo)(const char *netWorkId, void *info, uint32_t len);
} DistributedLedgerKey;

typedef enum {
    CATEGORY_UDID,
    CATEGORY_UUID,
    CATEGORY_NETWORK_ID,
} IdCategory;

typedef enum {
    REPORT_NONE,
    REPORT_CHANGE,
    REPORT_ONLINE,
    REPORT_OFFLINE,
} ReportCategory;

int32_t LnnInitDistributedLedger(void);
void LnnDeinitDistributedLedger(void);

ReportCategory LnnAddOnlineNode(NodeInfo *info);
ReportCategory LnnSetNodeOffline(const char *udid, ConnectionAddrType type, int32_t authId);
void LnnRemoveNode(const char *udid);
NodeInfo *LnnGetNodeInfoById(const char *id, IdCategory type);
bool LnnSetDLDeviceInfoName(const char *udid, const char *name);
bool LnnSetDLP2pInfo(const char *networkId, const P2pInfo *info);
const char *LnnConvertDLidToUdid(const char *id, IdCategory type);
int32_t LnnConvertDlId(const char *srcId, IdCategory srcIdType, IdCategory dstIdType,
    char *dstIdBuf, uint32_t dstIdBufLen);
short LnnGetCnnCode(const char *uuid, DiscoveryType type);
int32_t LnnGetBasicInfoByUdid(const char *udid, NodeBasicInfo *basicInfo);
int32_t LnnGetLaneCount(int32_t laneId);
int32_t LnnSetLaneCount(int32_t laneId, int32_t num);
int32_t LnnGetDLHeartbeatTimestamp(const char *networkId, uint64_t *timestamp);
int32_t LnnSetDLHeartbeatTimestamp(const char *networkId, const uint64_t timestamp);
bool LnnGetOnlineStateById(const char *id, IdCategory type);
int32_t LnnGetLnnRelation(const char *id, IdCategory type, uint8_t *relation, uint32_t len);
int32_t LnnSetDLConnCapability(const char *networkId, uint64_t connCapability);
int32_t LnnSetDLNodeAddr(const char *id, IdCategory type, const char *addr);
int32_t LnnGetAllAuthSeq(const char *udid, int64_t *authSeq, uint32_t num);
const NodeInfo *LnnGetOnlineNodeByUdidHash(const char *recvUdidHash);
void LnnRefreshDeviceOnlineStateAndDevIdInfo(const char *pkgName, DeviceInfo *device,
    const InnerDeviceInfoAddtions *addtions);
int32_t LnnUpdateNodeInfo(NodeInfo *newInfo);
int32_t LnnAddMetaInfo(NodeInfo *info);
int32_t LnnDeleteMetaInfo(const char *udid, ConnectionAddrType type);
#ifdef __cplusplus
}
#endif

#endif // LNN_DISTRIBUTED_NET_LEDGER_H