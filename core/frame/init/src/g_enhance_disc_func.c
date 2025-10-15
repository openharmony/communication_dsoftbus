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

#include "g_enhance_disc_func.h"

#include <securec.h>
#include <dlfcn.h>

#include "softbus_error_code.h"
#ifndef NULL
#define NULL 0
#endif

DiscEnhanceFuncList g_discEnhanceFuncList = { NULL };

DiscEnhanceFuncList *DiscEnhanceFuncListGet(void)
{
    return &g_discEnhanceFuncList;
}

static void DiscFeatureRegisterEnhanceFunc(void *soHandle)
{
#if !defined(__G_ENHANCE_DISC_FUNC_PACK_BROADCAST_MGR_VIRTUAL)
    g_discEnhanceFuncList.schedulerStartBroadcast = dlsym(soHandle, "SchedulerStartBroadcast");
    g_discEnhanceFuncList.schedulerUpdateBroadcast = dlsym(soHandle, "SchedulerUpdateBroadcast");
    g_discEnhanceFuncList.schedulerSetBroadcastData = dlsym(soHandle, "SchedulerSetBroadcastData");
    g_discEnhanceFuncList.schedulerStopBroadcast = dlsym(soHandle, "SchedulerStopBroadcast");
    g_discEnhanceFuncList.schedulerSetBroadcastParam = dlsym(soHandle, "SchedulerSetBroadcastParam");
    g_discEnhanceFuncList.schedulerInitBroadcast = dlsym(soHandle, "SchedulerInitBroadcast");
    g_discEnhanceFuncList.schedulerDeinitBroadcast = dlsym(soHandle, "SchedulerDeinitBroadcast");
#endif

#if !defined(__G_ENHANCE_DISC_FUNC_PACK_INNER_DISC_COAP_VIRTUAL)
    g_discEnhanceFuncList.discCoapProcessDeviceInfo = dlsym(soHandle, "DiscCoapProcessDeviceInfo");
#ifdef DSOFTBUS_FEATURE_DISC_SHARE_COAP
    g_discEnhanceFuncList.discCoapAssembleCapData = dlsym(soHandle, "DiscCoapAssembleCapData");
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
    g_discEnhanceFuncList.discFillBtype = dlsym(soHandle, "DiscFillBtype");
    g_discEnhanceFuncList.discCoapAssembleBdata = dlsym(soHandle, "DiscCoapAssembleBdata");
#endif

#ifdef DSOFTBUS_FEATURE_DISC_COAP
    g_discEnhanceFuncList.discCoapFillServiceData = dlsym(soHandle, "DiscCoapFillServiceData");
#endif /* DSOFTBUS_FEATURE_DISC_COAP */
    return;
}

int32_t DiscRegisterEnhanceFunc(void *soHandle)
{
    g_discEnhanceFuncList.discTouchBleInit = dlsym(soHandle, "DiscTouchBleInit");
    g_discEnhanceFuncList.discShareBleInit = dlsym(soHandle, "DiscShareBleInit");
    g_discEnhanceFuncList.discApproachBleInit = dlsym(soHandle, "DiscApproachBleInit");
    g_discEnhanceFuncList.discVLinkBleInit = dlsym(soHandle, "DiscVLinkBleInit");
    g_discEnhanceFuncList.discVLinkBleDeinit = dlsym(soHandle, "DiscVLinkBleDeinit");
    g_discEnhanceFuncList.discTouchBleDeinit = dlsym(soHandle, "DiscTouchBleDeinit");
    g_discEnhanceFuncList.discApproachBleDeinit = dlsym(soHandle, "DiscApproachBleDeinit");
    g_discEnhanceFuncList.discShareBleDeinit = dlsym(soHandle, "DiscShareBleDeinit");

    g_discEnhanceFuncList.discApproachBleEventInit = dlsym(soHandle, "DiscApproachBleEventInit");
    g_discEnhanceFuncList.discVLinkBleEventInit = dlsym(soHandle, "DiscVLinkBleEventInit");
    g_discEnhanceFuncList.discTouchBleEventInit = dlsym(soHandle, "DiscTouchBleEventInit");
    g_discEnhanceFuncList.discApproachBleEventDeinit = dlsym(soHandle, "DiscApproachBleEventDeinit");
    g_discEnhanceFuncList.discVLinkBleEventDeinit = dlsym(soHandle, "DiscVLinkBleEventDeinit");
    g_discEnhanceFuncList.discTouchBleEventDeinit = dlsym(soHandle, "DiscTouchBleEventDeinit");
    g_discEnhanceFuncList.discCoapReportNotification = dlsym(soHandle, "DiscCoapReportNotification");
 
    g_discEnhanceFuncList.discUsbDeinit = dlsym(soHandle, "DiscUsbDeinit");
    g_discEnhanceFuncList.discUsbInit = dlsym(soHandle, "DiscUsbInit");
    g_discEnhanceFuncList.discOopBleInit = dlsym(soHandle, "DiscOopBleInit");
    g_discEnhanceFuncList.discOopBleDeinit = dlsym(soHandle, "DiscOopBleDeinit");
    g_discEnhanceFuncList.discOopBleEventInit = dlsym(soHandle, "DiscOopBleEventInit");
    g_discEnhanceFuncList.discOopBleEventDeinit = dlsym(soHandle, "DiscOopBleEventDeinit");
    g_discEnhanceFuncList.discPcCollaborationBleInit = dlsym(soHandle, "DiscPcCollaborationBleInit");
    g_discEnhanceFuncList.discPcCollaborationEventInit = dlsym(soHandle, "DiscPcCollaborationEventInit");

    g_discEnhanceFuncList.distUpdatePublishParam = dlsym(soHandle, "DistUpdatePublishParam");
    g_discEnhanceFuncList.distDiscoveryStartActionPreLink = dlsym(soHandle, "DistDiscoveryStartActionPreLink");
    g_discEnhanceFuncList.distDiscoveryStopActionPreLink = dlsym(soHandle, "DistDiscoveryStopActionPreLink");
    g_discEnhanceFuncList.distPublishStopActionPreLink = dlsym(soHandle, "DistPublishStopActionPreLink");
    g_discEnhanceFuncList.distMgrStartActionReply = dlsym(soHandle, "DistMgrStartActionReply");
    g_discEnhanceFuncList.distGetActionParam = dlsym(soHandle, "DistGetActionParam");
    g_discEnhanceFuncList.distActionProcessConPacket = dlsym(soHandle, "DistActionProcessConPacket");
    g_discEnhanceFuncList.distActionInit = dlsym(soHandle, "DistActionInit");
    g_discEnhanceFuncList.distActionDeinit = dlsym(soHandle, "DistActionDeinit");
    g_discEnhanceFuncList.isUnknownDevice = dlsym(soHandle, "IsUnknownDevice");
    (void)DiscFeatureRegisterEnhanceFunc(soHandle);
    return SOFTBUS_OK;
}