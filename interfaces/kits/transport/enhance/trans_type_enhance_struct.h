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
#ifndef TRANS_TYPE_ENHANCED_STRUCT_H
#define TRANS_TYPE_ENHANCED_STRUCT_H

#include "stdbool.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_MAC_LEN  18
#define MAX_IP_LEN  46

typedef enum {
    PARA_ACTION = 1,   /**< support action. */
    PARA_BUTT,
} ParaType;

typedef struct {
    uint32_t actionId;
} ActionAddr;

typedef struct {
    ParaType type;
    union {
        ActionAddr action;
    };
    bool enable160M;    /**< support 160M. */
    bool accountInfo;
} LinkPara;

typedef struct {
    char srcMac[MAX_MAC_LEN];
    char dstMac[MAX_MAC_LEN];
    int32_t connectType;
    char localIp[MAX_IP_LEN];
    char remoteIp[MAX_IP_LEN];
} MacInfo;
#ifdef __cplusplus
}
#endif
#endif // TRANS_TYPE_ENHANCED_H