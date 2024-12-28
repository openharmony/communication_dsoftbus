/*
 * Copyright (C) 2024 Huawei Device Co., Ltd.
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

#include "nstackx.h"

#include "nstackx_error.h"

int32_t NSTACKX_RegisterDevice(const NSTACKX_LocalDeviceInfo *localDeviceInfo)
{
    (void)localDeviceInfo;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterDeviceName(const char *devName)
{
    (void)devName;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterDeviceAn(const NSTACKX_LocalDeviceInfo *localDeviceInfo, uint64_t deviceHash)
{
    (void)localDeviceInfo;
    (void)deviceHash;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterDeviceV2(const NSTACKX_LocalDeviceInfoV2 *localDeviceInfo)
{
    (void)localDeviceInfo;
    return NSTACKX_EOK;
}

int NSTACKX_DFinderSetEventFunc(void *softobj, DFinderEventFunc func)
{
    (void)softobj;
    (void)func;
    return NSTACKX_EOK;
}

int NSTACKX_DFinderDump(const char **argv, uint32_t argc, void *softObj, DFinderDumpFunc dump)
{
    (void)argv;
    (void)argc;
    (void)softObj;
    (void)dump;
    return NSTACKX_EOK;
}

int32_t NSTACKX_Init(const NSTACKX_Parameter *parameter)
{
    (void)parameter;
    return NSTACKX_EOK;
}

int32_t NSTACKX_InitV2(const NSTACKX_Parameter *parameter, bool isNotifyPerDevice)
{
    (void)parameter;
    (void)isNotifyPerDevice;
    return NSTACKX_EOK;
}

int32_t NSTACKX_ThreadInit(void)
{
    return NSTACKX_EOK;
}

void NSTACKX_ThreadDeinit(void)
{
    return;
}

void NSTACKX_Deinit(void)
{
    return;
}

int32_t NSTACKX_StartDeviceFind(void)
{
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceFindAn(uint8_t mode)
{
    (void)mode;
    return NSTACKX_EOK;
}

int32_t NSTACKX_StopDeviceFind(void)
{
    return NSTACKX_EOK;
}

int32_t NSTACKX_SubscribeModule(void)
{
    return NSTACKX_EOK;
}

int32_t NSTACKX_UnsubscribeModule(void)
{
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    (void)capabilityBitmapNum;
    (void)capabilityBitmap;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SetFilterCapability(uint32_t capabilityBitmapNum, uint32_t capabilityBitmap[])
{
    (void)capabilityBitmapNum;
    (void)capabilityBitmap;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SetDeviceListAgingTime(uint32_t agingTime)
{
    (void)agingTime;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SetMaxDeviceNum(uint32_t maxDeviceNum)
{
    (void)maxDeviceNum;
    return NSTACKX_EOK;
}

int32_t NSTACKX_ScreenStatusChange(bool isScreenOn)
{
    (void)isScreenOn;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterServiceData(const char *serviceData)
{
    (void)serviceData;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterBusinessData(const char *businessData)
{
    (void)businessData;
    return NSTACKX_EOK;
}

int32_t NSTACKX_RegisterExtendServiceData(const char *extendServiceData)
{
    (void)extendServiceData;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SendMsg(const char *moduleName, const char *deviceId, const uint8_t *data,
                        uint32_t len)
{
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SendMsgDirect(const char *moduleName, const char *deviceId, const uint8_t *data,
    uint32_t len, const char *ipaddr, uint8_t sendType)
{
    (void)moduleName;
    (void)deviceId;
    (void)data;
    (void)len;
    (void)ipaddr;
    (void)sendType;
    return NSTACKX_EOK;
}

int32_t NSTACKX_GetDeviceList(NSTACKX_DeviceInfo *deviceList, uint32_t *deviceCountPtr)
{
    (void)deviceList;
    (void)deviceCountPtr;
    return NSTACKX_EOK;
}

int32_t NSTACKX_InitRestart(const NSTACKX_Parameter *parameter)
{
    (void)parameter;
    return NSTACKX_EOK;
}

void NSTACKX_StartDeviceFindRestart(void)
{
    return;
}

int32_t NSTACKX_StartDeviceDiscovery(const NSTACKX_DiscoverySettings *discoverySettings)
{
    (void)discoverySettings;
    return NSTACKX_EOK;
}

int32_t NSTACKX_StartDeviceDiscoveryWithConfig(const DFinderDiscConfig *discConfig)
{
    (void)discConfig;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SendDiscoveryRsp(const NSTACKX_ResponseSettings *responseSettings)
{
    (void)responseSettings;
    return NSTACKX_EOK;
}

int32_t NSTACKX_SendNotification(const NSTACKX_NotificationConfig *config)
{
    (void)config;
    return NSTACKX_EOK;
}

int32_t NSTACKX_StopSendNotification(uint8_t businessType)
{
    (void)businessType;
    return NSTACKX_EOK;
}

int32_t NSTACKX_DFinderRegisterLog(DFinderLogCallback userLogCallback)
{
    (void)userLogCallback;
    return NSTACKX_EOK;
}
