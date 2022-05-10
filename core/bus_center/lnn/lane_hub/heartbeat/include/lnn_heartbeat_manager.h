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

#ifndef LNN_HEARTBEAT_MANAGER_H
#define LNN_HEARTBEAT_MANAGER_H

#include "softbus_common.h"
#include "lnn_node_info.h"

#ifdef __cplusplus
extern "C" {
#endif

#define HB_SHA_HASH_LEN 32
#define HB_USER_ID_LEN 65

typedef enum {
    HB_IMPL_TYPE_BLE = 0,
    HB_IMPL_TYPE_MAX,
} LnnHeartbeatImplType;

typedef struct {
    void (*onRelay)(const char *udidHash, ConnectionAddrType type);
    int32_t (*onRecvHigherWeight)(const char *udidHash, int32_t weight, ConnectionAddrType type);
    int32_t (*onUpdateDev)(DeviceInfo *device, int32_t weight, int32_t localMasterWeight);
} LnnHeartbeatImplCallback;

int32_t LnnHbMgrInit(void);
int32_t LnnHbMgrOneCycleBegin(void);
int32_t LnnHbMgrOneCycleEnd(void);
int32_t LnnHbMgrStop(void);
int32_t LnnHbMgrUpdateLocalInfo(void);
void LnnHbMgrDeinit(void);

void LnnDumpHbMgrUpdateList(void);
void LnnDumpHbOnlineNodeList(void);

#ifdef __cplusplus
}
#endif
#endif /* LNN_HEARTBEAT_MANAGER_H */