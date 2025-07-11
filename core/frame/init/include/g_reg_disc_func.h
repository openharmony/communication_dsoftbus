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

#ifndef G_REG_DISC_FUNC_H
#define G_REG_DISC_FUNC_H

#include "g_enhance_disc_func.h"
#include "softbus_common.h"
#include "stdint.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef int32_t (*DiscCoapSendRspFunc)(const DeviceInfo *deviceInfo, uint8_t bType);
typedef int32_t (*DiscGetDisplayNameFunc)(char *displayName, uint32_t length, uint32_t remainLen);
typedef int32_t (*DiscCoapParseKeyValueStrFunc)(const char *src, const char *key, char *outValue, uint32_t outLen);
typedef void (*DiscSoftbusBleSetHandleIdFunc)(uint32_t handleId);
typedef int32_t (*OnRaiseHandDeviceFoundFunc)(RaiseHandDeviceInfo *deviceInfo);
typedef uint32_t (*GetDiscCapabilityFunc)(void);
typedef uint16_t (*DiscBleGetDeviceType)(void);
typedef int32_t (*DiscBleGetDeviceIdHash)(uint8_t *devIdHash, uint32_t len);
typedef int32_t (*DiscBleGetShortUserIdHash)(uint8_t *hashStr, uint32_t len);
typedef void (*DiscVirlinkLinklessRegisterListenerFunc)(
    const struct DiscVirlinkConnStatusListener *listener);
typedef int (*DiscVirlinkLinklessVirtualSendFunc)(const char *networkId, const uint8_t *data, uint32_t dataLen);
typedef int (*DiscVirlinkLinklessRegisterRecvCallbackFunc)(DiscVirlinkLinklessRecvCb recvCb);

typedef struct TagDiscOpenFuncList {
    DiscCoapSendRspFunc discCoapSendRsp;
    DiscGetDisplayNameFunc discGetDisplayName;
    DiscCoapParseKeyValueStrFunc discCoapParseKeyValueStr;
    DiscSoftbusBleSetHandleIdFunc discSoftbusBleSetHandleId;
    OnRaiseHandDeviceFoundFunc onRaiseHandDeviceFound;
    GetDiscCapabilityFunc getDiscCapability;
    DiscBleGetDeviceType discBleGetDeviceType;
    DiscBleGetDeviceIdHash discBleGetDeviceIdHash;
    DiscBleGetShortUserIdHash discBleGetShortUserIdHash;
    DiscVirlinkLinklessRegisterListenerFunc discVirlinkLinklessRegisterListener;
    DiscVirlinkLinklessVirtualSendFunc discVirlinkLinklessVirtualSend;
    DiscVirlinkLinklessRegisterRecvCallbackFunc discVirlinkLinklessRegisterRecvCallback;
} DiscOpenFuncList;

#ifdef __cplusplus
}
#endif

#endif