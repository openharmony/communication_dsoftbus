/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#include "disc_coap.h"

#include <pthread.h>
#include "disc_nstackx_adapter.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_mem_interface.h"

#define INT32_MAX_BIT_NUM 32
#define MAX_CAP_NUM (CAPABILITY_NUM * INT32_MAX_BIT_NUM)
#define MAX_SERVICE_DATA 64

typedef struct {
    uint32_t allCap[CAPABILITY_NUM];
    int16_t capCount[MAX_CAP_NUM];
    bool isUpdate;
    bool isEmpty;
    pthread_mutex_t lock;
} DiscCoapInfo;

static DiscCoapInfo *g_publishMgr = NULL;
static DiscCoapInfo *g_subscribeMgr = NULL;

static int32_t RegisterAllCapBitmap(uint32_t capBitmapNum, const uint32_t inCapBitmap[], DiscCoapInfo *info,
    uint32_t count)
{
    if (info == NULL || capBitmapNum == 0 || capBitmapNum > CAPABILITY_NUM || count > MAX_CAP_NUM) {
        LOG_ERR("invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        LOG_INFO("register input bitmap = [%u].", inCapBitmap[i]);
        for (uint32_t pos = 0; pos < count; pos++) {
            if (((inCapBitmap[i] >> (pos % INT32_MAX_BIT_NUM)) & 0x1) == 0) {
                continue;
            }
            if ((info->capCount)[pos] == 0) {
                (info->allCap)[i] |= (0x1 << (pos % INT32_MAX_BIT_NUM));
                info->isUpdate = true;
            }
            (info->capCount)[pos]++;
        }
        LOG_INFO("register all cap bitmap = [%u].", (info->allCap)[i]);
    }
    return SOFTBUS_OK;
}

static int32_t  UnregisterAllCapBitmap(uint32_t capBitmapNum, const uint32_t inCapBitmap[], DiscCoapInfo *info,
    uint32_t count)
{
    if (info == NULL || capBitmapNum == 0 || capBitmapNum > CAPABILITY_NUM || count > MAX_CAP_NUM) {
        LOG_ERR("invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }

    info->isEmpty = true;
    info->isUpdate = false;
    for (uint32_t i = 0; i < capBitmapNum; i++) {
        LOG_INFO("unregister input bitmap = [%u].", inCapBitmap[i]);
        for (uint32_t pos = 0; pos < count; pos++) {
            if (((inCapBitmap[i] >> (pos % INT32_MAX_BIT_NUM)) & 0x1) == 0) {
                continue;
            }
            (info->capCount)[pos]--;
            if ((info->capCount)[pos] <= 0) {
                (info->allCap)[i] &= (~(0x1 << (pos % INT32_MAX_BIT_NUM)));
                (info->capCount)[pos] = 0;
                info->isUpdate = true;
            }
        }
        if ((info->allCap)[i] != 0) {
            info->isEmpty = false;
        }
        LOG_INFO("register all cap bitmap = [%u].", (info->allCap)[i]);
    }
    return SOFTBUS_OK;
}

static int32_t CoapPublish(const PublishOption *option)
{
    if (option == NULL || g_publishMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(g_publishMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("merge publish capability failed.");
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_publishMgr->lock));
            LOG_ERR("register all capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("register service data to dfinder failed.");
        return SOFTBUS_ERR;
    }
    if (DiscCoapStartDiscovery(ACTIVE_PUBLISH) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("coap start publish failed.");
        return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
    }
    (void)pthread_mutex_unlock(&(g_publishMgr->lock));
    LOG_INFO("coap publish service.");
    return SOFTBUS_OK;
}

static int32_t CoapUnPublish(const PublishOption *option)
{
    if (option == NULL || g_publishMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_publishMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("cancel a publish capability failed.");
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_publishMgr->lock));
            LOG_ERR("register all capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("register service data to dfinder failed.");
        return SOFTBUS_ERR;
    }
    if (g_publishMgr->isEmpty) {
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_publishMgr->lock));
            LOG_ERR("coap unpublish failed.");
            return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
        }
    }
    (void)pthread_mutex_unlock(&(g_publishMgr->lock));
    LOG_INFO("coap unpublish service.");
    return SOFTBUS_OK;
}

static int32_t CoapStartScan(const PublishOption *option)
{
    if (option == NULL || g_publishMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(g_publishMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("merge publish capability failed.");
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_publishMgr->lock));
            LOG_ERR("register all capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("register service data to dfinder failed.");
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&(g_publishMgr->lock));
    LOG_INFO("coap start passive publish.");
    return SOFTBUS_OK;
}

static int32_t CoapStoptScan(const PublishOption *option)
{
    if (option == NULL || g_publishMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (pthread_mutex_lock(&(g_publishMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_publishMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("merge publish capability failed.");
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_publishMgr->isUpdate) {
        if (DiscCoapRegisterCapability(CAPABILITY_NUM, g_publishMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_publishMgr->lock));
            LOG_ERR("register all capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL;
        }
    }
    if (DiscCoapRegisterServiceData(option->capabilityData, option->dataLen) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_publishMgr->lock));
        LOG_ERR("register service data to dfinder failed.");
        return SOFTBUS_ERR;
    }
    (void)pthread_mutex_unlock(&(g_publishMgr->lock));
    LOG_INFO("coap stop passive publish.");
    return SOFTBUS_OK;
}

static int32_t CoapSubscribe(const SubscribeOption *option)
{
    if (option == NULL || g_subscribeMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_subscribeMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("merge discovery capability failed.");
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
            LOG_ERR("set all filter capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
    LOG_INFO("coap start passive discovery.");
    return SOFTBUS_OK;
}

static int32_t CoapUnsubscribe(const SubscribeOption *option)
{
    if (option == NULL || g_subscribeMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_subscribeMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("merge discovery capability failed.");
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
            LOG_ERR("set all filter capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
    LOG_INFO("coap stop passive discovery.");
    return SOFTBUS_OK;
}

static int32_t CoapStartAdvertise(const SubscribeOption *option)
{
    if (option == NULL || g_subscribeMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_subscribeMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (RegisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr, MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("merge discovery capability failed.");
        return SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
            LOG_ERR("set all filter capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("coap stop discovery failed.");
        return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
    }
    if (DiscCoapStartDiscovery(ACTIVE_DISCOVERY) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("coap start advertise failed.");
        return SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL;
    }
    (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
    LOG_INFO("coap start active discovery.");
    return SOFTBUS_OK;
}

static int32_t CoapStopAdvertise(const SubscribeOption *option)
{
    if (option == NULL || g_subscribeMgr == NULL) {
        return SOFTBUS_INVALID_PARAM;
    }

    if (pthread_mutex_lock(&(g_subscribeMgr->lock)) != 0) {
        LOG_ERR("pthread mutex lock failed.");
        return SOFTBUS_LOCK_ERR;
    }
    if (UnregisterAllCapBitmap(CAPABILITY_NUM, option->capabilityBitmap, g_subscribeMgr,  MAX_CAP_NUM) != SOFTBUS_OK) {
        (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
        LOG_ERR("cancel a discovery capability failed.");
        return SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL;
    }
    if (g_subscribeMgr->isUpdate) {
        if (DiscCoapSetFilterCapability(CAPABILITY_NUM, g_subscribeMgr->allCap) != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
            LOG_ERR("set all filter capability to dfinder failed.");
            return SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL;
        }
    }
    if (g_subscribeMgr->isEmpty) {
        if (DiscCoapStopDiscovery() != SOFTBUS_OK) {
            (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
            LOG_ERR("coap stop advertise failed.");
            return SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL;
        }
    }
    (void)pthread_mutex_unlock(&(g_subscribeMgr->lock));
    LOG_INFO("coap stop active discovery.");
    return SOFTBUS_OK;
}

static DiscoveryFuncInterface g_discCoapFuncInterface = {
    .Publish = CoapPublish,
    .StartScan = CoapStartScan,
    .Unpublish = CoapUnPublish,
    .StopScan = CoapStoptScan,
    .StartAdvertise = CoapStartAdvertise,
    .Subscribe = CoapSubscribe,
    .StopAdvertise = CoapStopAdvertise,
    .Unsubscribe = CoapUnsubscribe
};

static DiscCoapInfo *NewDiscCoapInfo()
{
    DiscCoapInfo *coapInfo = (DiscCoapInfo*)SoftBusCalloc(sizeof(DiscCoapInfo));
    if (coapInfo == NULL) {
        return NULL;
    }
    if (pthread_mutex_init(&(coapInfo->lock), NULL) != 0) {
        SoftBusFree(coapInfo);
        return NULL;
    }
    return coapInfo;
}

static void DeleteDiscCoapInfo(DiscCoapInfo *coapInfo)
{
    if (coapInfo == NULL) {
        return;
    }
    (void)pthread_mutex_destroy(&(coapInfo->lock));
    SoftBusFree(coapInfo);
}

static void DeinitCoapManager()
{
    DeleteDiscCoapInfo(g_publishMgr);
    g_publishMgr = NULL;
    DeleteDiscCoapInfo(g_subscribeMgr);
    g_subscribeMgr = NULL;
}

static int32_t InitCoapManager()
{
    if (g_publishMgr == NULL) {
        g_publishMgr = NewDiscCoapInfo();
    }
    if (g_subscribeMgr == NULL) {
        g_subscribeMgr = NewDiscCoapInfo();
    }
    if (g_publishMgr == NULL || g_subscribeMgr == NULL) {
        DeinitCoapManager();
        return SOFTBUS_DISCOVER_COAP_INIT_FAIL;
    }
    return SOFTBUS_OK;
}

DiscoveryFuncInterface *DiscCoapInit(DiscInnerCallback *discInnerCb)
{
    if (InitCoapManager() != SOFTBUS_OK) {
        LOG_ERR("coap manager init failed.");
        return NULL;
    }
    if (DiscNstackxInit() != SOFTBUS_OK) {
        LOG_ERR("dfinder init failed.");
        DeinitCoapManager();
        return NULL;
    }
    if (DiscCoapRegisterCb(discInnerCb) != SOFTBUS_OK) {
        LOG_ERR("register coap callback to dfinder failed.");
        DiscCoapDeinit();
        return NULL;
    }
    LOG_INFO("coap discovery init success.");
    return &g_discCoapFuncInterface;
}

void DiscCoapDeinit(void)
{
    DeinitCoapManager();
    DiscNstackxDeinit();
}