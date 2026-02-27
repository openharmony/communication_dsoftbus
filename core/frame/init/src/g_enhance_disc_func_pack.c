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
#include "g_enhance_disc_func_pack.h"

#include "disc_coap_capability_public.h"
#include "disc_log.h"
#include "g_enhance_disc_func.h"
#include "softbus_broadcast_manager.h"
#include "softbus_error_code.h"
#include "softbus_init_common.h"

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_BROADCAST_MGR_VIRTUAL)

int32_t SchedulerStartBroadcastPacked(int32_t bcId, BroadcastContentType bcType, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerStartBroadcast) != SOFTBUS_OK) {
        (void)bcType;
        return StartBroadcasting(bcId, bcParam, bcPacket);
    }
    return pfnDiscEnhanceFuncList->schedulerStartBroadcast(bcId, bcType, bcParam, bcPacket);
}

int32_t SchedulerUpdateBroadcastPacked(int32_t bcId, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerUpdateBroadcast) != SOFTBUS_OK) {
        return UpdateBroadcasting(bcId, bcParam, bcPacket);
    }
    return pfnDiscEnhanceFuncList->schedulerUpdateBroadcast(bcId, bcParam, bcPacket);
}

int32_t SchedulerSetBroadcastDataPacked(int32_t bcId, const BroadcastPacket *bcPacket)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerSetBroadcastData) != SOFTBUS_OK) {
        return SetBroadcastingData(bcId, bcPacket);
    }
    return pfnDiscEnhanceFuncList->schedulerSetBroadcastData(bcId, bcPacket);
}

int32_t SchedulerStopBroadcastPacked(int32_t bcId)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerStopBroadcast) != SOFTBUS_OK) {
        return StopBroadcasting(bcId);
    }
    return pfnDiscEnhanceFuncList->schedulerStopBroadcast(bcId);
}

int32_t SchedulerSetBroadcastParamPacked(int32_t bcId, const BroadcastParam *bcParam)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerSetBroadcastParam) != SOFTBUS_OK) {
        return SetBroadcastingParam(bcId, bcParam);
    }
    return pfnDiscEnhanceFuncList->schedulerSetBroadcastParam(bcId, bcParam);
}

int32_t SchedulerInitBroadcastPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerInitBroadcast) != SOFTBUS_OK) {
        return InitBroadcastMgr();
    }
    return pfnDiscEnhanceFuncList->schedulerInitBroadcast();
}

int32_t SchedulerDeinitBroadcastPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->schedulerDeinitBroadcast) != SOFTBUS_OK) {
        return DeInitBroadcastMgr();
    }
    return pfnDiscEnhanceFuncList->schedulerDeinitBroadcast();
}
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_INNER_DISC_COAP_VIRTUAL)
int32_t DiscCoapProcessDeviceInfoPacked(const NSTACKX_DeviceInfo *nstackxInfo, DeviceInfo *devInfo,
    const DiscInnerCallback discCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapProcessDeviceInfo) != SOFTBUS_OK) {
        return DiscCoapProcessDeviceInfo(nstackxInfo, devInfo, discCb);
    }
    return pfnDiscEnhanceFuncList->discCoapProcessDeviceInfo(nstackxInfo, devInfo, discCb);
}

int32_t DiscCoapAssembleBdataPacked(const unsigned char *capabilityData, uint32_t dataLen, char *businessData,
    uint32_t businessDataLen)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (pfnDiscEnhanceFuncList == NULL ||
        DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapAssembleBdata) != SOFTBUS_OK) {
        return DiscCoapAssembleBdata(capabilityData, dataLen, businessData, businessDataLen);
    }
    return pfnDiscEnhanceFuncList->discCoapAssembleBdata(capabilityData, dataLen, businessData, businessDataLen);
}

#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
int32_t DiscCoapAssembleCapDataPacked(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData,
    uint32_t outLen)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapAssembleCapData) != SOFTBUS_OK) {
        return DiscCoapAssembleCapData(capability, capabilityData, dataLen, outData, outLen);
    }
    return pfnDiscEnhanceFuncList->discCoapAssembleCapData(capability, capabilityData, dataLen, outData, outLen);
}

void DiscCoapUpdateAbilityPacked(uint32_t capability, const char *capabilityData, uint32_t dataLen,
    bool isPublish, bool isStart)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapUpdateAbility) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discCoapUpdateAbility(capability, capabilityData, dataLen, isPublish, isStart);
}
#endif /* DSOFTBUS_FEATURE_DISC_COAP */

int32_t DiscCoapExtInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapExtInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discCoapExtInit();
}

void DiscCoapExtDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapExtDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discCoapExtDeinit();
}

int32_t DiscFillBtypePacked(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discFillBtype) != SOFTBUS_OK) {
        return DiscFillBtype(capability, allCap, discSet);
    }
    return pfnDiscEnhanceFuncList->discFillBtype(capability, allCap, discSet);
}
#endif

static int32_t BleStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t BleStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void BleLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    (void)status;
    (void)ifnameIdx;
}

static void BleUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool BleIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discVirtualFuncInterface = {
    .Publish = BleStartActivePublish,
    .StartScan = BleStartPassivePublish,
    .Unpublish = BleStopActivePublish,
    .StopScan = BleStopPassivePublish,
    .StartAdvertise = BleStartActiveDiscovery,
    .Subscribe = BleStartPassiveDiscovery,
    .Unsubscribe = BleStopPassiveDiscovery,
    .StopAdvertise = BleStopActiveDiscovery,
    .LinkStatusChanged = BleLinkStatusChanged,
    .UpdateLocalDeviceInfo = BleUpdateLocalDeviceInfo
};

static DiscoveryBleDispatcherInterface g_virtualBleInterface = {
    .IsConcern = BleIsConcern,
    .mediumInterface = &g_discVirtualFuncInterface,
};

DiscoveryBleDispatcherInterface *DiscTouchBleInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discTouchBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discTouchBleInit(discInnerCb);
}

DiscoveryBleDispatcherInterface *DiscOopBleInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discOopBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discOopBleInit(discInnerCb);
}

DiscoveryBleDispatcherInterface *DiscPcCollaborationInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discPcCollaborationBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discPcCollaborationBleInit(discInnerCb);
}

DiscoveryBleDispatcherInterface *DiscShareBleInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discShareBleInit(discInnerCb);
}

DiscoveryBleDispatcherInterface *DiscApproachBleInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discApproachBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discApproachBleInit(discInnerCb);
}

DiscoveryBleDispatcherInterface *DiscVLinkBleInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discVLinkBleInit) != SOFTBUS_OK) {
        return &g_virtualBleInterface;
    }
    return pfnDiscEnhanceFuncList->discVLinkBleInit(discInnerCb);
}

void DiscShareBleDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareBleDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discShareBleDeinit();
}

void DiscApproachBleDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discApproachBleDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discApproachBleDeinit();
}

void DiscVLinkBleDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discVLinkBleDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discVLinkBleDeinit();
}

void DiscTouchBleDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discTouchBleDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discTouchBleDeinit();
}

void DiscOopBleDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discOopBleDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discOopBleDeinit();
}

void PcCollaborationManagerDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->pcCollaborationManagerDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->pcCollaborationManagerDeinit();
}
 
void DiscPcCollaborationEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->pcCollaborationEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->pcCollaborationEventDeinit();
}

void DiscCoapReportNotificationPacked(const NSTACKX_NotificationConfig *notification)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapReportNotification) != SOFTBUS_OK) {
        return;
    }
    pfnDiscEnhanceFuncList->discCoapReportNotification(notification);
    return;
}

#ifdef DSOFTBUS_FEATURE_DISC_COAP
int32_t DiscCoapFillServiceDataPacked(const PublishOption *option, char *outData, uint32_t outDataLen,
    uint32_t allCap)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discCoapFillServiceData) != SOFTBUS_OK) {
        return DiscCoapFillServiceData(option, outData, outDataLen, allCap);
    }
    return pfnDiscEnhanceFuncList->discCoapFillServiceData(option, outData, outDataLen, allCap);
}
#endif /* DSOFTBUS_FEATURE_DISC_COAP */

int32_t DiscApproachBleEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discApproachBleEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discApproachBleEventInit();
}

int32_t DiscVLinkBleEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discVLinkBleEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discVLinkBleEventInit();
}

int32_t DiscTouchBleEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discTouchBleEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discTouchBleEventInit();
}

int32_t DiscOopBleEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discOopBleEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discOopBleEventInit();
}

int32_t DiscPcCollaborationEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discPcCollaborationEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discPcCollaborationEventInit();
}

void DiscTouchBleEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discTouchBleEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discTouchBleEventDeinit();
}

void DiscApproachBleEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discApproachBleEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discApproachBleEventDeinit();
}

void DiscVLinkBleEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discVLinkBleEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discVLinkBleEventDeinit();
}

void DiscOopBleEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discOopBleEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discOopBleEventDeinit();
}

int32_t DiscShareNfcEventInitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareNfcEventInit) != SOFTBUS_OK) {
        return SOFTBUS_OK;
    }
    return pfnDiscEnhanceFuncList->discShareNfcEventInit();
}

void DiscShareNfcEventDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareNfcEventDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discShareNfcEventDeinit();
}

DiscoveryNfcDispatcherInterface *DiscShareNfcInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareNfcInit) != SOFTBUS_OK) {
        return NULL;
    }
    return pfnDiscEnhanceFuncList->discShareNfcInit(discInnerCb);
}

void DiscShareNfcDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discShareNfcDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discShareNfcDeinit();
}

static int32_t UsbDiscStartActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStopActivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStopPassivePublish(const PublishOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static int32_t UsbDiscStartPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_OK;
}

static int32_t UsbDiscStopPassiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_OK;
}

static int32_t UsbDiscStopActiveDiscovery(const SubscribeOption *option)
{
    (void)option;
    return SOFTBUS_NOT_IMPLEMENT;
}

static void UsbDiscLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    (void)status;
    (void)ifnameIdx;
}

static void UsbDiscUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    (void)type;
}

static bool UsbDiscIsConcern(uint32_t capability)
{
    (void)capability;
    return false;
}

static DiscoveryFuncInterface g_discUsbFuncInterface = {
    .Publish = UsbDiscStartActivePublish,
    .StartScan = UsbDiscStartPassivePublish,
    .Unpublish = UsbDiscStopActivePublish,
    .StopScan = UsbDiscStopPassivePublish,
    .StartAdvertise = UsbDiscStartActiveDiscovery,
    .Subscribe = UsbDiscStartPassiveDiscovery,
    .Unsubscribe = UsbDiscStopPassiveDiscovery,
    .StopAdvertise = UsbDiscStopActiveDiscovery,
    .LinkStatusChanged = UsbDiscLinkStatusChanged,
    .UpdateLocalDeviceInfo = UsbDiscUpdateLocalDeviceInfo
};

static DiscoveryUsbDispatcherInterface g_usbDiscInterface = {
    .IsConcern = UsbDiscIsConcern,
    .mediumInterface = &g_discUsbFuncInterface,
};

DiscoveryUsbDispatcherInterface *DiscUsbInitPacked(DiscInnerCallback *discInnerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discUsbInit) != SOFTBUS_OK) {
        return &g_usbDiscInterface;
    }
    return pfnDiscEnhanceFuncList->discUsbInit(discInnerCb);
}

void DiscUsbDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();
    if (DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->discUsbDeinit) != SOFTBUS_OK) {
        return;
    }
    return pfnDiscEnhanceFuncList->discUsbDeinit();
}

int32_t DistUpdatePublishParamPacked(const char *cust, const char *extCust, bool isStart)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distUpdatePublishParam);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, SOFTBUS_OK, DISC_BLE, "not find DistUpdatePublishParam");
    return pfnDiscEnhanceFuncList->distUpdatePublishParam(cust, extCust, isStart);
}

int32_t DistDiscoveryStartActionPreLinkPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distDiscoveryStartActionPreLink);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, SOFTBUS_OK, DISC_BLE, "not find DistDiscoveryStartActionPreLink");
    return pfnDiscEnhanceFuncList->distDiscoveryStartActionPreLink();
}

int32_t DistDiscoveryStopActionPreLinkPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distDiscoveryStopActionPreLink);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, SOFTBUS_OK, DISC_BLE, "not find DistDiscoveryStopActionPreLink");
    return pfnDiscEnhanceFuncList->distDiscoveryStopActionPreLink();
}

int32_t DistPublishStopActionPreLinkPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distPublishStopActionPreLink);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, SOFTBUS_OK, DISC_BLE, "not find DistPublishStopActionPreLink");
    return pfnDiscEnhanceFuncList->distPublishStopActionPreLink();
}

void DistGetActionParamPacked(DiscActionParam *action)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distGetActionParam);
    DISC_CHECK_AND_RETURN_LOGD(ret == SOFTBUS_OK, DISC_BLE, "not find DistGetActionParam");
    return pfnDiscEnhanceFuncList->distGetActionParam(action);
}

bool DistActionProcessConPacketPacked(DeviceWrapper *wrapperDevice, const uint8_t *key, uint32_t len)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distActionProcessConPacket);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, false, DISC_BLE, "not find DistActionProcessConPacket");
    return pfnDiscEnhanceFuncList->distActionProcessConPacket(wrapperDevice, key, len);
}

int32_t DistActionInitPacked(DiscActionUpdateBleCallback *updateAdvCb, DiscInnerCallback *innerCb)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distActionInit);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, SOFTBUS_OK, DISC_BLE, "not find DistActionInit");
    return pfnDiscEnhanceFuncList->distActionInit(updateAdvCb, innerCb);
}

void DistActionDeinitPacked(void)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->distActionDeinit);
    DISC_CHECK_AND_RETURN_LOGD(ret == SOFTBUS_OK, DISC_BLE, "not find DistActionDeinit");
    return pfnDiscEnhanceFuncList->distActionDeinit();
}

bool IsUnknownDevicePacked(const char *bleMacAddr)
{
    DiscEnhanceFuncList *pfnDiscEnhanceFuncList = DiscEnhanceFuncListGet();

    int32_t ret = DiscCheckFuncPointer((void *)pfnDiscEnhanceFuncList->isUnknownDevice);
    DISC_CHECK_AND_RETURN_RET_LOGD(ret == SOFTBUS_OK, false, DISC_BLE, "not find isUnknownDevice");
    return pfnDiscEnhanceFuncList->isUnknownDevice(bleMacAddr);
}