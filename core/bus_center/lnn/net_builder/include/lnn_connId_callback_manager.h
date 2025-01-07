/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
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

#ifndef LNN_CONNID_CALLBACK_MANAGER
#define LNN_CONNID_CALLBACK_MANAGER

#include <stdint.h>

#include "common_list.h"
#include "softbus_bus_center.h"
#include "softbus_common.h"


#ifdef __cplusplus
extern "C" {
#endif

typedef struct {
    void (*lnnServerJoinExtCallback)(const ConnectionAddr *addr, int32_t returnRet);
} LnnServerJoinExtCallBack;

typedef struct {
    ListNode node;
    char udid[UDID_BUF_LEN];
    ConnectionAddr sessionAddr;
    LnnServerJoinExtCallBack callBack;
    uint32_t connId;
} ConnIdCbInfo;

int32_t LnnInitConnIdCallbackManager(void);
void LnnDeinitConnIdCallbackManager(void);

int32_t AddConnIdCallbackInfoItem(const ConnectionAddr *sessionAddr, const LnnServerJoinExtCallBack *callBack,
    uint32_t connId, char *peerUdid);
int32_t DelConnIdCallbackInfoItem(uint32_t connId);
void InvokeCallbackForJoinExt(const char *udid, int32_t result);
int32_t GetConnIdCbInfoByAddr(const ConnectionAddr *addr, ConnIdCbInfo *dupItem);


#ifdef __cplusplus
}
#endif

#endif // LNN_CONNID_CALLBACK_MANAGER