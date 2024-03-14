/*
 * Copyright (C) 2021-2023 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_DEVICE_LOCAL_H
#define NSTACKX_DEVICE_LOCAL_H

#include "nstackx_device.h"
#include "coap_app.h"

#ifdef __cplusplus
extern "C" {
#endif

enum {
    REGISTER_TYPE_UPDATE_ALL,
    REGISTER_TYPE_UPDATE_SPECIFIED,
};

struct LocalIface;

int LocalDeviceInit(EpollDesc epollfd);
void LocalDeviceDeinit(void);

void ResetLocalDeviceTaskCount(uint8_t isBusy);

int RegisterLocalDeviceV2(const NSTACKX_LocalDeviceInfoV2 *devInfo, int registerType);
void ConfigureLocalDeviceName(const char *localDeviceName);
void SetLocalDeviceHash(uint64_t deviceHash);
int SetLocalDeviceCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[]);
int32_t SetLocalDeviceServiceData(const char *serviceData);

void SetLocalDeviceBusinessType(uint8_t businessType);
uint8_t GetLocalDeviceBusinessType(void);

int SetLocalDeviceBusinessData(const char *data, bool unicast);
int32_t LocalizeNotificationMsg(const char *msg);
uint8_t GetLocalDeviceMode(void);
void SetLocalDeviceMode(uint8_t mode);

#ifndef DFINDER_USE_MINI_NSTACKX
int32_t SetLocalDeviceExtendServiceData(const char *extendServiceData);
#ifndef _WIN32
void DetectLocalIface(void *arg);
#endif
#endif

const char *GetLocalDeviceId(void);
DeviceInfo *GetLocalDeviceInfo(void);
const char *GetLocalDeviceNetworkName(void);

int GetBroadcastIp(const struct LocalIface *iface, char *ipStr, size_t ipStrLen);
const struct in_addr *GetLocalIfaceIp(const struct LocalIface *iface);
const char *GetLocalIfaceIpStr(const struct LocalIface *iface);
const char *GetLocalIfaceName(const struct LocalIface *iface);
CoapCtxType *LocalIfaceGetCoapCtx(const char *ifname);
#ifndef DFINDER_USE_MINI_NSTACKX
CoapCtxType *LocalIfaceGetCoapCtxByRemoteIp(const struct in_addr *remoteIp, uint8_t serverType);
#endif
int AddLocalIface(const char *ifname, const struct in_addr *ip);
void RemoveLocalIface(const char *ifname);
void DestroyLocalIface(struct LocalIface *iface, bool moduleDeinit);

#ifdef NSTACKX_DFINDER_HIDUMP
int LocalIfaceDump(char *buf, size_t size);
#endif

#ifdef __cplusplus
}
#endif

#endif
