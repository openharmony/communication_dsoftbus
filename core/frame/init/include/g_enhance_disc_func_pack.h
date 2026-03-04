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
#ifndef G_ENHANCE_DISC_FUNC_PACK_H
#define G_ENHANCE_DISC_FUNC_PACK_H

#include "broadcast_scheduler_type_struct.h"
#include "disc_manager.h"
#include "disc_interface.h"
#include "disc_ble_dispatcher.h"
#include "disc_nfc_dispatcher.h"
#include "disc_usb_dispatcher.h"
#include "disc_ble_utils_struct.h"
#include "nstackx.h"
#include "stdint.h"
#include "stdbool.h"
#include "softbus_broadcast_type.h"
#include "softbus_adapter_thread.h"

#ifdef __cplusplus
extern "C" {
#endif
#if !defined(__G_ENHANCE_DISC_FUNC_PACK_BROADCAST_MGR_VIRTUAL)
int32_t SchedulerStartBroadcastPacked(int32_t bcId, BroadcastContentType bcType, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket);

int32_t SchedulerUpdateBroadcastPacked(int32_t bcId, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket);
int32_t SchedulerSetBroadcastDataPacked(int32_t bcId, const BroadcastPacket *bcPacket);
int32_t SchedulerStopBroadcastPacked(int32_t bcId);

int32_t SchedulerSetBroadcastParamPacked(int32_t bcId, const BroadcastParam *bcParam);
int32_t SchedulerInitBroadcastPacked(void);
int32_t SchedulerDeinitBroadcastPacked(void);
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_INNER_DISC_COAP_VIRTUAL)
int32_t DiscCoapAssembleBdataPacked(
    const unsigned char *capabilityData, uint32_t dataLen, char *businessData, uint32_t businessDataLen);
int32_t DiscCoapProcessDeviceInfoPacked(const NSTACKX_DeviceInfo *nstackxInfo, DeviceInfo *devInfo,
    const DiscInnerCallback discCb);
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
int32_t DiscCoapAssembleCapDataPacked(uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData,
    uint32_t outLen);
void DiscCoapUpdateAbilityPacked(uint32_t capability, const char *capabilityData, uint32_t dataLen,
    bool isPublish, bool isStart);
#endif

int32_t DiscCoapExtInitPacked(void);
void DiscCoapExtDeinitPacked(void);

#endif

int32_t DiscFillBtypePacked(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet);

DiscoveryBleDispatcherInterface *DiscTouchBleInitPacked(DiscInnerCallback *discInnerCb);
DiscoveryBleDispatcherInterface *DiscOopBleInitPacked(DiscInnerCallback *discInnerCb);
DiscoveryBleDispatcherInterface *DiscShareBleInitPacked(DiscInnerCallback *discInnerCb);
DiscoveryBleDispatcherInterface *DiscApproachBleInitPacked(DiscInnerCallback *discInnerCb);
DiscoveryBleDispatcherInterface *DiscVLinkBleInitPacked(DiscInnerCallback *discInnerCb);
DiscoveryBleDispatcherInterface *DiscPcCollaborationInitPacked(DiscInnerCallback *discInnerCb);
void DiscShareBleDeinitPacked(void);
void DiscApproachBleDeinitPacked(void);
void DiscVLinkBleDeinitPacked(void);
void DiscTouchBleDeinitPacked(void);
void DiscOopBleDeinitPacked(void);
void PcCollaborationManagerDeinitPacked(void);

void DiscCoapReportNotificationPacked(const NSTACKX_NotificationConfig *notification);
#ifdef DSOFTBUS_FEATURE_DISC_COAP
int32_t DiscCoapFillServiceDataPacked(const PublishOption *option, char *outData, uint32_t outDataLen,
    uint32_t allCap);
#endif /* DSOFTBUS_FEATURE_DISC_COAP */

int32_t DiscApproachBleEventInitPacked(void);
int32_t DiscVLinkBleEventInitPacked(void);
int32_t DiscTouchBleEventInitPacked(void);
int32_t DiscOopBleEventInitPacked(void);
int32_t DiscPcCollaborationEventInitPacked(void);
int32_t DiscShareNfcEventInitPacked(void);
void DiscPcCollaborationEventDeinitPacked(void);
void DiscTouchBleEventDeinitPacked(void);
void DiscApproachBleEventDeinitPacked(void);
void DiscVLinkBleEventDeinitPacked(void);
void DiscOopBleEventDeinitPacked(void);
void DiscShareNfcEventDeinitPacked(void);
DiscoveryUsbDispatcherInterface *DiscUsbInitPacked(DiscInnerCallback *discInnerCb);
void DiscUsbDeinitPacked(void);

int32_t DistUpdatePublishParamPacked(const char *cust, const char *extCust, bool isStart);
int32_t DistDiscoveryStartActionPreLinkPacked(void);
int32_t DistDiscoveryStopActionPreLinkPacked(void);
int32_t DistPublishStopActionPreLinkPacked(void);
void DistGetActionParamPacked(DiscActionParam *action);
bool DistActionProcessConPacketPacked(DeviceWrapper *wrapperDevice, const uint8_t *key, uint32_t len);
int32_t DistActionInitPacked(DiscActionUpdateBleCallback *updateAdvCb, DiscInnerCallback *innerCb);
void DistActionDeinitPacked(void);
bool IsUnknownDevicePacked(const char *bleMacAddr);
DiscoveryNfcDispatcherInterface *DiscShareNfcInitPacked(DiscInnerCallback *discInnerCb);
void DiscShareNfcDeinitPacked(void);
#ifdef __cplusplus
}
#endif

#endif
