/*
 * Copyright (c) 2022-2024 Huawei Device Co., Ltd.
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

#ifndef LNN_HEARTBEAT_UTILS_H
#define LNN_HEARTBEAT_UTILS_H

#include "data_level_inner.h"
#include "softbus_common.h"
#include "lnn_heartbeat_utils_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

bool LnnVisitHbTypeSet(VisitHbTypeCb callback, LnnHeartbeatType *typeSet, void *data);

LnnHeartbeatType LnnConvertConnAddrTypeToHbType(ConnectionAddrType addrType);
ConnectionAddrType LnnConvertHbTypeToConnAddrType(LnnHeartbeatType type);
int32_t LnnConvertHbTypeToId(LnnHeartbeatType type);
bool LnnHasActiveConnection(const char *networkId, ConnectionAddrType addrType);
bool LnnCheckSupportedHbType(LnnHeartbeatType *srcType, LnnHeartbeatType *dstType);
int32_t LnnGetShortAccountHash(uint8_t *accountHash, uint32_t len);
int32_t LnnGenerateHexStringHash(const unsigned char *str, char *hashStr, uint32_t len);
int32_t LnnGenerateBtMacHash(const char *btMac, int32_t brMacLen, char *brMacHash, int32_t hashLen);
bool LnnIsSupportBurstFeature(const char *networkId);
bool LnnIsLocalSupportBurstFeature(void);
void LnnDumpLocalBasicInfo(void);
void LnnDumpOnlineDeviceInfo(void);
uint32_t GenerateRandomNumForHb(uint32_t randMin, uint32_t randMax);
bool LnnIsMultiDeviceOnline(void);
bool LnnIsSupportHeartbeatCap(uint32_t hbCapacity, HeartbeatCapability capaBit);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_UTILS_H */
