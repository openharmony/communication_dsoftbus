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

#include "disc_nfc_dispatcher.h"

#include <securec.h>

#include "disc_event.h"
#include "disc_log.h"
#include "disc_manager.h"
#include "g_enhance_disc_func_pack.h"
#include "softbus_adapter_thread.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define DISPATCHER_SIZE 4

static DiscoveryNfcDispatcherInterface *g_nfcDispatchers[DISPATCHER_SIZE];
static SoftBusMutex g_nfcDispatchersLock;

static DiscoveryFuncInterface *FindNfcFuncInterface(uint32_t capability)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexLock(&g_nfcDispatchersLock) == SOFTBUS_OK, NULL, DISC_INIT, "lock fail");
    for (uint32_t i = 0; i < ARRAY_SIZE(g_nfcDispatchers); i++) {
        if (g_nfcDispatchers[i] == NULL) {
            continue;
        }
        if (g_nfcDispatchers[i]->IsConcern != NULL && g_nfcDispatchers[i]->IsConcern(capability)) {
            SoftBusMutexUnlock(&g_nfcDispatchersLock);
            return g_nfcDispatchers[i]->mediumInterface;
        }
    }
    SoftBusMutexUnlock(&g_nfcDispatchersLock);
    return NULL;
}

static int32_t NfcDispatchPublishOption(const PublishOption *option, DiscoverMode mode,
    InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_NFC, "option is null");
    DiscoveryFuncInterface *interface = FindNfcFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        DISC_LOGE(DISC_NFC,
            "dispatch publish action fail: no implement support capability. capabilityBitmap=%{public}u",
            option->capabilityBitmap[0]);
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = mode,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_NFC_PUBLISH, extra);
        return SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL;
    }
    switch (type) {
        case PUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Publish(option) : interface->StartScan(option);
        case UNPUBLISH_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->Unpublish(option) : interface->StopScan(option);
        default:
            DISC_LOGE(DISC_NFC,
                "dispatch publish action fail: unsupport type. type=%{public}d, capability=%{public}u",
                type, option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL;
    }
}

static int32_t NfcDispatchSubscribeOption(const SubscribeOption *option, DiscoverMode mode,
    InterfaceFuncType type)
{
    DISC_CHECK_AND_RETURN_RET_LOGE(option != NULL, SOFTBUS_INVALID_PARAM, DISC_NFC, "option is null");
    DiscoveryFuncInterface *interface = FindNfcFuncInterface(option->capabilityBitmap[0]);
    if (interface == NULL) {
        DISC_LOGE(DISC_NFC, "dispatch subcribe action fail: no implement support capability.");
        DiscAuditExtra extra = {
            .result = DISC_AUDIT_DISCONTINUE,
            .errcode = SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL,
            .auditType = AUDIT_EVENT_MSG_ERROR,
            .discMode = mode,
            .broadcastFreq = option->freq,
            .localCapabilityBitmap = option->capabilityBitmap[0],
        };
        DISC_AUDIT(AUDIT_SCENE_NFC_SUBSCRIBE, extra);
        return SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL;
    }
    switch (type) {
        case STARTDISCOVERTY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StartAdvertise(option) : interface->Subscribe(option);
        case STOPDISCOVERY_FUNC:
            return mode == DISCOVER_MODE_ACTIVE ? interface->StopAdvertise(option) : interface->Unsubscribe(option);
        default:
            DISC_LOGE(DISC_NFC, "dispatch subcribe action fail: unsupport. type=%{public}d, capability=%{public}u",
                type, option->capabilityBitmap[0]);
            return SOFTBUS_DISCOVER_NFC_DISPATCHER_FAIL;
    }
}

 static int32_t NfcDispatchStartActivePublish(const PublishOption *option)
{
    return NfcDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, PUBLISH_FUNC);
}

static int32_t NfcDispatchStartPassivePublish(const PublishOption *option)
{
    return NfcDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, PUBLISH_FUNC);
}

static int32_t NfcDispatchStopActivePublish(const PublishOption *option)
{
    return NfcDispatchPublishOption(option, DISCOVER_MODE_ACTIVE, UNPUBLISH_FUNC);
}

static int32_t NfcDispatchStopPassivePublish(const PublishOption *option)
{
    return NfcDispatchPublishOption(option, DISCOVER_MODE_PASSIVE, UNPUBLISH_FUNC);
}

static int32_t NfcDispatchStartActiveDiscovery(const SubscribeOption *option)
{
    return NfcDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STARTDISCOVERTY_FUNC);
}

static int32_t NfcDispatchStartPassiveDiscovery(const SubscribeOption *option)
{
    return NfcDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STARTDISCOVERTY_FUNC);
}

static int32_t NfcDispatchStopActiveDiscovery(const SubscribeOption *option)
{
    return NfcDispatchSubscribeOption(option, DISCOVER_MODE_ACTIVE, STOPDISCOVERY_FUNC);
}

static int32_t NfcDispatchStopPassiveDiscovery(const SubscribeOption *option)
{
    return NfcDispatchSubscribeOption(option, DISCOVER_MODE_PASSIVE, STOPDISCOVERY_FUNC);
}

static void NfcDispatchLinkStatusChanged(LinkStatus status, int32_t ifnameIdx)
{
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_nfcDispatchersLock) == SOFTBUS_OK, DISC_INIT, "lock fail");
    for (uint32_t i = 0; i < ARRAY_SIZE(g_nfcDispatchers); i++) {
        if (g_nfcDispatchers[i] != NULL && g_nfcDispatchers[i]->mediumInterface != NULL &&
            g_nfcDispatchers[i]->mediumInterface->LinkStatusChanged != NULL) {
            g_nfcDispatchers[i]->mediumInterface->LinkStatusChanged(status, ifnameIdx);
        }
    }
    SoftBusMutexUnlock(&g_nfcDispatchersLock);
}

static void NfcDispatchUpdateLocalDeviceInfo(InfoTypeChanged type)
{
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_nfcDispatchersLock) == SOFTBUS_OK, DISC_INIT, "lock fail");
    for (uint32_t i = 0; i < ARRAY_SIZE(g_nfcDispatchers); i++) {
        if (g_nfcDispatchers[i] != NULL && g_nfcDispatchers[i]->mediumInterface != NULL &&
            g_nfcDispatchers[i]->mediumInterface->UpdateLocalDeviceInfo != NULL) {
            g_nfcDispatchers[i]->mediumInterface->UpdateLocalDeviceInfo(type);
        }
    }
    SoftBusMutexUnlock(&g_nfcDispatchersLock);
}

static DiscoveryFuncInterface g_discNfcFrameFuncInterface = {
    .Publish = NfcDispatchStartActivePublish,
    .StartScan = NfcDispatchStartPassivePublish,
    .Unpublish = NfcDispatchStopActivePublish,
    .StopScan = NfcDispatchStopPassivePublish,
    .StartAdvertise = NfcDispatchStartActiveDiscovery,
    .Subscribe = NfcDispatchStartPassiveDiscovery,
    .StopAdvertise = NfcDispatchStopActiveDiscovery,
    .Unsubscribe = NfcDispatchStopPassiveDiscovery,
    .LinkStatusChanged = NfcDispatchLinkStatusChanged,
    .UpdateLocalDeviceInfo = NfcDispatchUpdateLocalDeviceInfo,
};

static void DfxRecordNfcInitEnd(int32_t stage, int32_t reason)
{
    DiscEventExtra extra = { 0 };
    DiscEventExtraInit(&extra);
    extra.initType = NFC + 1;
    extra.errcode = reason;
    extra.result = (reason == SOFTBUS_OK) ? EVENT_STAGE_RESULT_OK : EVENT_STAGE_RESULT_FAILED;
    DISC_EVENT(EVENT_SCENE_INIT, stage, extra);

    if (stage != EVENT_STAGE_INIT && reason != SOFTBUS_OK) {
        DISC_EVENT(EVENT_SCENE_INIT, EVENT_STAGE_INIT, extra);
    }
}

DiscoveryFuncInterface *DiscNfcDispatcherInit(DiscInnerCallback *discInnerCb)
{
    if (discInnerCb == NULL) {
        DfxRecordNfcInitEnd(EVENT_STAGE_INIT, SOFTBUS_INVALID_PARAM);
        DISC_LOGE(DISC_INIT, "discInnerCb err");
        return NULL;
    }

    DISC_CHECK_AND_RETURN_RET_LOGE(SoftBusMutexInit(&g_nfcDispatchersLock, NULL) == SOFTBUS_OK, NULL,
        DISC_INIT, "init mutex fail");

    (void)memset_s(g_nfcDispatchers, sizeof(g_nfcDispatchers), 0, sizeof(g_nfcDispatchers));
    DISC_LOGI(DISC_INIT, "DiscNfcDispatcherInit");
    int32_t dispatcherSize = 0;

    DiscoveryNfcDispatcherInterface *nfcInterface = DiscShareNfcInitPacked(discInnerCb);
    if (nfcInterface == NULL) {
        DISC_LOGE(DISC_INIT, "DiscNfcInit err");
        DfxRecordNfcInitEnd(EVENT_STAGE_NFC_INIT, SOFTBUS_DISCOVER_MANAGER_INIT_FAIL);
        (void)SoftBusMutexDestroy(&g_nfcDispatchersLock);
        return NULL;
    }

    if (SoftBusMutexLock(&g_nfcDispatchersLock) != SOFTBUS_OK) {
        DISC_LOGE(DISC_INIT, "g_nfcDispatchersLock lock fail");
        DiscShareNfcDeinitPacked();
        (void)SoftBusMutexDestroy(&g_nfcDispatchersLock);
        return NULL;
    }
    g_nfcDispatchers[dispatcherSize++] = nfcInterface;
    SoftBusMutexUnlock(&g_nfcDispatchersLock);
    DfxRecordNfcInitEnd(EVENT_STAGE_NFC_INIT, SOFTBUS_OK);
    return &g_discNfcFrameFuncInterface;
}

void DiscNfcDispatcherDeinit(void)
{
    DISC_LOGI(DISC_INIT, "DiscNfcDispatcherDeinit");
    DISC_CHECK_AND_RETURN_LOGE(SoftBusMutexLock(&g_nfcDispatchersLock) == SOFTBUS_OK, DISC_INIT, "lock fail");
    for (uint32_t i = 0; i < ARRAY_SIZE(g_nfcDispatchers); i++) {
        g_nfcDispatchers[i] = NULL;
    }
    SoftBusMutexUnlock(&g_nfcDispatchersLock);

    DiscShareNfcDeinitPacked();
    (void)SoftBusMutexDestroy(&g_nfcDispatchersLock);
}