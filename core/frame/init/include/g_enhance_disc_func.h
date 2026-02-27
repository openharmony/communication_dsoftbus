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

#ifndef G_ENHANCE_DISC_FUNC_H
#define G_ENHANCE_DISC_FUNC_H

#include "broadcast_scheduler_type_struct.h"
#include "disc_ble_dispatcher_struct.h"
#include "disc_ble_utils_struct.h"
#include "disc_interface_struct.h"
#include "disc_manager_struct.h"
#include "disc_nfc_dispatcher_struct.h"
#include "disc_usb_dispatcher_struct.h"
#include "disc_virlink_adapter_struct.h"
#include "nstackx_struct.h"
#include "softbus_common.h"
#include "softbus_adapter_thread.h"
#include "softbus_broadcast_type_struct.h"

#ifdef __cplusplus
extern "C" {
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_BROADCAST_MGR_VIRTUAL)
typedef int32_t (*SchedulerStartBroadcastFunc)(int32_t bcId, BroadcastContentType bcType, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket);
typedef int32_t (*SchedulerUpdateBroadcastFunc)(int32_t bcId, const BroadcastParam *bcParam,
    const BroadcastPacket *bcPacket);
typedef int32_t (*SchedulerSetBroadcastDataFunc)(int32_t bcId, const BroadcastPacket *bcPacket);
typedef int32_t (*SchedulerStopBroadcastFunc)(int32_t bcId);
typedef int32_t (*SchedulerSetBroadcastParamFunc)(int32_t bcId, const BroadcastParam *bcParam);
typedef int32_t (*SchedulerInitBroadcastFunc)(void);
typedef int32_t (*SchedulerDeinitBroadcastFunc)(void);
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_INNER_DISC_COAP_VIRTUAL)
typedef int32_t (*DiscCoapProcessDeviceInfoFunc)(const NSTACKX_DeviceInfo *nstackxInfo, DeviceInfo *devInfo,
    const DiscInnerCallback discCb);
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
typedef int32_t (*DiscCoapAssembleCapDataFunc)(
    uint32_t capability, const char *capabilityData, uint32_t dataLen, char *outData, uint32_t outLen);
typedef void (*DiscCoapUpdateAbilityFunc)(uint32_t capability, const char *capabilityData, uint32_t dataLen,
    bool isPublish, bool isStart);

#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */
typedef int32_t (*DiscFillBtypeFunc)(uint32_t capability, uint32_t allCap, NSTACKX_DiscoverySettings *discSet);
#endif

typedef DiscoveryBleDispatcherInterface *(*DiscTouchBleInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryBleDispatcherInterface *(*DiscShareBleInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryBleDispatcherInterface *(*DiscApproachBleInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryBleDispatcherInterface *(*DiscVLinkBleInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryUsbDispatcherInterface *(*DiscUsbInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryBleDispatcherInterface *(*DiscPcCollaborationInitFunc)(DiscInnerCallback *discInnerCb);
typedef DiscoveryNfcDispatcherInterface *(*DiscShareNfcInitFunc)(DiscInnerCallback *discInnerCb);
typedef void (*DiscVLinkBleDeinitFunc)(void);
typedef void (*DiscTouchBleDeinitFunc)(void);
typedef void (*DiscApproachBleDeinitFunc)(void);
typedef void (*DiscShareBleDeinitFunc)(void);
typedef void (*DiscUsbDeinitFunc)(void);
typedef void (*DiscShareNfcDeinitFunc)(void);
typedef int32_t (*DiscApproachBleEventInitFunc)(void);
typedef int32_t (*DiscVLinkBleEventInitFunc)(void);
typedef int32_t (*DiscTouchBleEventInitFunc)(void);
typedef int32_t (*DiscShareNfcEventInitFunc)(void);
typedef void (*DiscApproachBleEventDeinitFunc)(void);
typedef void (*DiscVLinkBleEventDeinitFunc)(void);
typedef void (*DiscTouchBleEventDeinitFunc)(void);
typedef void (*DiscShareNfcEventDeinitFunc)(void);
typedef void (*DiscCoapReportNotificationFunc)(const NSTACKX_NotificationConfig *notification);
#ifdef DSOFTBUS_FEATURE_DISC_COAP
typedef int32_t (*DiscCoapFillServiceDataFunc)(const PublishOption *option,
                                               char *outData, uint32_t outDataLen, uint32_t allCap);
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
typedef int32_t (*DiscCoapAssembleBdataFunc)(
    const unsigned char *capabilityData, uint32_t dataLen, char *businessData, uint32_t businessDataLen);
typedef DiscoveryBleDispatcherInterface *(*DiscOopBleInitFunc)(DiscInnerCallback *discInnerCb);
typedef void (*DiscOopBleDeinitFunc)(void);
typedef int32_t (*DiscOopBleEventInitFunc)(void);
typedef void (*DiscOopBleEventDeinitFunc)(void);
typedef int32_t (*DiscPcCollaborationEventInitFunc)(void);
typedef void (*DiscPcCollaborationDeinitFunc)(void);
typedef void (*DiscPcCollaborationEventDeinitFunc)(void);

typedef int32_t (*DistUpdatePublishParamFunc)(const char *cust, const char *extCust, bool isStart);
typedef int32_t (*DistDiscoveryStartActionPreLinkFunc)(void);
typedef int32_t (*DistDiscoveryStopActionPreLinkFunc)(void);
typedef int32_t (*DistPublishStopActionPreLinkFunc)(void);
typedef int32_t (*DistMgrStartActionReplyFunc)(DistActionContext *ctx);
typedef void (*DistGetActionParamFunc)(DiscActionParam *action);
typedef bool (*DistActionProcessConPacketFunc)(DeviceWrapper *wrapperDevice, const uint8_t *key, uint32_t len);

typedef int32_t (*DistActionInitFunc)(DiscActionUpdateBleCallback *updateAdvCb, DiscInnerCallback *innerCb);
typedef void (*DistActionDeinitFunc)(void);
typedef bool (*IsUnknownDeviceFunc)(const char *bleMacStr);

typedef int32_t (*DiscCoapExtInitFunc)(void);
typedef void (*DiscCoapExtDeinitFunc)(void);

typedef struct TagDiscEnhanceFuncList {
    DiscTouchBleInitFunc discTouchBleInit;
    DiscShareBleInitFunc discShareBleInit;
    DiscApproachBleInitFunc discApproachBleInit;
    DiscVLinkBleInitFunc discVLinkBleInit;
    DiscVLinkBleDeinitFunc discVLinkBleDeinit;
    DiscTouchBleDeinitFunc discTouchBleDeinit;
    DiscApproachBleDeinitFunc discApproachBleDeinit;
    DiscShareBleDeinitFunc discShareBleDeinit;
    DiscApproachBleEventInitFunc discApproachBleEventInit;
    DiscVLinkBleEventInitFunc discVLinkBleEventInit;
    DiscTouchBleEventInitFunc discTouchBleEventInit;
    DiscShareNfcEventInitFunc discShareNfcEventInit;
    DiscApproachBleEventDeinitFunc discApproachBleEventDeinit;
    DiscVLinkBleEventDeinitFunc discVLinkBleEventDeinit;
    DiscTouchBleEventDeinitFunc discTouchBleEventDeinit;
    DiscShareNfcEventDeinitFunc discShareNfcEventDeinit;
    
    DiscCoapReportNotificationFunc discCoapReportNotification;
#ifdef DSOFTBUS_FEATURE_DISC_COAP
    DiscCoapFillServiceDataFunc discCoapFillServiceData;
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
    DiscCoapAssembleBdataFunc discCoapAssembleBdata;

    DiscUsbInitFunc discUsbInit;
    DiscUsbDeinitFunc discUsbDeinit;

    DiscOopBleInitFunc discOopBleInit;
    DiscOopBleDeinitFunc discOopBleDeinit;
    DiscOopBleEventInitFunc discOopBleEventInit;
    DiscOopBleEventDeinitFunc discOopBleEventDeinit;

    DiscPcCollaborationInitFunc discPcCollaborationBleInit;
    DiscPcCollaborationEventInitFunc discPcCollaborationEventInit;
    DiscPcCollaborationDeinitFunc pcCollaborationManagerDeinit;
    DiscPcCollaborationEventDeinitFunc pcCollaborationEventDeinit;

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_BROADCAST_MGR_VIRTUAL)
    SchedulerStartBroadcastFunc schedulerStartBroadcast;
    SchedulerUpdateBroadcastFunc schedulerUpdateBroadcast;
    SchedulerSetBroadcastDataFunc schedulerSetBroadcastData;
    SchedulerStopBroadcastFunc schedulerStopBroadcast;

    SchedulerSetBroadcastParamFunc schedulerSetBroadcastParam;
    SchedulerInitBroadcastFunc schedulerInitBroadcast;
    SchedulerDeinitBroadcastFunc schedulerDeinitBroadcast;
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_INNER_DISC_COAP_VIRTUAL)
    DiscCoapProcessDeviceInfoFunc discCoapProcessDeviceInfo;
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
    DiscCoapUpdateAbilityFunc discCoapUpdateAbility;
    DiscCoapAssembleCapDataFunc discCoapAssembleCapData;
#endif /* DSOFTBUS_FEATURE_DISC_SHARE_COAP */
    DiscFillBtypeFunc discFillBtype;
#endif

    DistUpdatePublishParamFunc distUpdatePublishParam;
    DistDiscoveryStartActionPreLinkFunc distDiscoveryStartActionPreLink;
    DistDiscoveryStopActionPreLinkFunc distDiscoveryStopActionPreLink;
    DistPublishStopActionPreLinkFunc distPublishStopActionPreLink;
    DistMgrStartActionReplyFunc distMgrStartActionReply;
    DistGetActionParamFunc distGetActionParam;
    DistActionProcessConPacketFunc distActionProcessConPacket;
    DistActionInitFunc distActionInit;
    DistActionDeinitFunc distActionDeinit;
    IsUnknownDeviceFunc isUnknownDevice;
    DiscCoapExtInitFunc discCoapExtInit;
    DiscCoapExtDeinitFunc discCoapExtDeinit;

    DiscShareNfcInitFunc discShareNfcInit;
    DiscShareNfcDeinitFunc discShareNfcDeinit;
} DiscEnhanceFuncList;

DiscEnhanceFuncList *DiscEnhanceFuncListGet(void);
int32_t DiscRegisterEnhanceFunc(void *soHandle);

#ifdef __cplusplus
}
#endif

#endif