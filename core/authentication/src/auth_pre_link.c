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
#include "auth_pre_link.h"

#include <securec.h>
#include <stdatomic.h>
#include "anonymizer.h"
#include "auth_connection.h"
#include "auth_deviceprofile.h"
#include "auth_log.h"
#include "auth_request.h"
#include "auth_session_message.h"
#include "bus_center_manager.h"
#include "device_profile_listener.h"
#include "legacy/softbus_adapter_hitrace.h"
#include "g_enhance_lnn_func.h"
#include "g_enhance_lnn_func_pack.h"
#include "lnn_app_bind_interface.h"
#include "lnn_decision_db.h"
#include "lnn_heartbeat_ctrl.h"
#include "lnn_local_net_ledger.h"
#include "lnn_ohos_account_adapter.h"
#include "lnn_map.h"
#include "lnn_net_builder.h"
#include "softbus_adapter_mem.h"
#include "softbus_init_common.h"
#include "wifi_direct_manager.h"

#define AUTH_GEN_CERT_PARA_EXPIRE_TIME 500
#define AUTH_GEN_CERT_PARA_TIME 10

static SoftBusList g_authPreLinkList;
static SoftBusList g_authGenCertParallelList;
static bool g_isInitAuthPreLinkList = false;
static bool g_isInitAuthGenCertList = false;

static int32_t AuthGenCertParallelLock(void)
{
    return SoftBusMutexLock(&g_authGenCertParallelList.lock);
}

static void AuthGenCertParallelUnLock(void)
{
    (void)SoftBusMutexUnlock(&g_authGenCertParallelList.lock);
}

int32_t InitAuthGenCertParallelList(void)
{
    if (g_isInitAuthGenCertList) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_authGenCertParallelList.lock, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth gen cert parallel init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_authGenCertParallelList.list);
    g_authGenCertParallelList.cnt = 0;
    g_isInitAuthGenCertList = true;
    return SOFTBUS_OK;
}

static bool IsAuthGenCertParaNodeExist(int32_t requestId)
{
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        return false;
    }
    AuthGenCertNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authGenCertParallelList.list, AuthGenCertNode, node) {
        if (item->requestId == requestId) {
            AuthGenCertParallelUnLock();
            return true;
        }
    }
    AuthGenCertParallelUnLock();
    return false;
}

int32_t AddAuthGenCertParaNode(int32_t requestId)
{
    if (IsAuthGenCertParaNodeExist(requestId)) {
        AUTH_LOGE(AUTH_CONN, "auth gen cert parallel node exists");
        return SOFTBUS_ALREADY_EXISTED;
    }
    AuthGenCertNode *item = (AuthGenCertNode *)SoftBusCalloc(sizeof(AuthGenCertNode));
    if (item == NULL) {
        AUTH_LOGE(AUTH_CONN, "item malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }

    item->requestId = requestId;
    item->isValid = false;
    item->softbusCertChain = NULL;
    atomic_store_explicit(&item->isParallelGen, 1, memory_order_release);
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        SoftBusFree(item);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_authGenCertParallelList.list, &item->node);
    g_authGenCertParallelList.cnt++;
    AuthGenCertParallelUnLock();
    AUTH_LOGI(AUTH_CONN, "create new gencert parallel, authreq=%{public}d", requestId);
    return SOFTBUS_OK;
}

static int32_t FindAuthGenCertParaNodeById(int32_t requestId, AuthGenCertNode **genCertParaNode)
{
    if (genCertParaNode == NULL) {
        AUTH_LOGE(AUTH_CONN, "genCertParaNode pointer is null");
        return SOFTBUS_INVALID_PARAM;
    }
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthGenCertNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authGenCertParallelList.list, AuthGenCertNode, node) {
        if (item->requestId == requestId) {
            *genCertParaNode = item;
            AuthGenCertParallelUnLock();
            return SOFTBUS_OK;
        }
    }
    AuthGenCertParallelUnLock();
    return SOFTBUS_NOT_FIND;
}

int32_t UpdateAuthGenCertParaNode(int32_t requestId, bool isValid, SoftbusCertChain *softbusCertChain)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(softbusCertChain != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "CertChain is NULL");
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthGenCertNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authGenCertParallelList.list, AuthGenCertNode, node) {
        if (item->requestId == requestId) {
            item->isValid = isValid;
            item->softbusCertChain = softbusCertChain;
            atomic_store_explicit(&item->isParallelGen, 0, memory_order_release);
            AuthGenCertParallelUnLock();
            return SOFTBUS_OK;
        }
    }
    AuthGenCertParallelUnLock();
    return SOFTBUS_NOT_FIND;
}

int32_t FindAndWaitAuthGenCertParaNodeById(int32_t requestId, AuthGenCertNode **genCertParaNode)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(genCertParaNode != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "CertParaNode is NULL");
    int32_t ret = 0;
    int32_t totalSleepMs = 0;
    ret = FindAuthGenCertParaNodeById(requestId, genCertParaNode);
    if (ret != SOFTBUS_OK) {
        return ret;
    }
    if ((*genCertParaNode)->softbusCertChain == NULL) {
        DelAuthGenCertParaNodeById(requestId);
        *genCertParaNode = NULL;
        return SOFTBUS_AUTH_TIMEOUT;
    }
    while (((*genCertParaNode)->isParallelGen) && totalSleepMs < AUTH_GEN_CERT_PARA_EXPIRE_TIME) {
        SoftBusSleepMs(AUTH_GEN_CERT_PARA_TIME);
        totalSleepMs += AUTH_GEN_CERT_PARA_TIME;
    }
    if (totalSleepMs >= AUTH_GEN_CERT_PARA_EXPIRE_TIME || (*genCertParaNode)->isValid == false) {
        DelAuthGenCertParaNodeById(requestId);
        *genCertParaNode = NULL;
        return SOFTBUS_AUTH_TIMEOUT;
    }
    if (*genCertParaNode == NULL) {
        return SOFTBUS_AUTH_TIMEOUT;
    }
    return SOFTBUS_OK;
}

void DelAuthGenCertParaNodeById(int32_t requestId)
{
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        return;
    }
    AuthGenCertNode *item = NULL;
    AuthGenCertNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authGenCertParallelList.list, AuthGenCertNode, node) {
        if (item->requestId == requestId) {
            ListDelete(&item->node);
            FreeSoftbusChainPacked(item->softbusCertChain);
            SoftBusFree(item->softbusCertChain);
            item->softbusCertChain = NULL;
            SoftBusFree(item);
            if (g_authGenCertParallelList.cnt == 0) {
                AUTH_LOGI(AUTH_CONN, "auth gencert parallel list cnt is 0.");
            } else {
                g_authGenCertParallelList.cnt--;
            }
            AuthGenCertParallelUnLock();
            return;
        }
    }
    AuthGenCertParallelUnLock();
}

void DeinitAuthGenCertParallelList(void)
{
    if (AuthGenCertParallelLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth generate certificate parallel lock fail");
        return;
    }
    AuthGenCertNode *item = NULL;
    AuthGenCertNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authGenCertParallelList.list, AuthGenCertNode, node) {
        ListDelete(&item->node);
        FreeSoftbusChainPacked(item->softbusCertChain);
        SoftBusFree(item->softbusCertChain);
        item->softbusCertChain = NULL;
        SoftBusFree(item);
        if (g_authGenCertParallelList.cnt == 0) {
            AUTH_LOGI(AUTH_CONN, "auth gencert parallel list cnt is 0.");
        } else {
            g_authGenCertParallelList.cnt--;
        }
    }
    g_isInitAuthGenCertList = false;
    AuthGenCertParallelUnLock();
    SoftBusMutexDestroy(&g_authGenCertParallelList.lock);
}

static int32_t AuthPreLinkLock(void)
{
    return SoftBusMutexLock(&g_authPreLinkList.lock);
}

static void AuthPreLinkUnlock(void)
{
    (void)SoftBusMutexUnlock(&g_authPreLinkList.lock);
}

int32_t InitAuthPreLinkList(void)
{
    if (g_isInitAuthPreLinkList) {
        return SOFTBUS_OK;
    }
    if (SoftBusMutexInit(&g_authPreLinkList.lock, NULL) != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link init fail");
        return SOFTBUS_NO_INIT;
    }
    ListInit(&g_authPreLinkList.list);
    g_authPreLinkList.cnt = 0;
    g_isInitAuthPreLinkList = true;
    return SOFTBUS_OK;
}

static bool PreLinkCheckHasPtk(const char *uuid)
{
    if (uuid == NULL) {
        AUTH_LOGE(AUTH_FSM, "uuid is null");
        return false;
    }
    struct WifiDirectManager *wdMgr = GetWifiDirectManager();
    if (wdMgr == NULL || wdMgr->linkHasPtk == NULL) {
        AUTH_LOGE(AUTH_FSM, "get wifiDirect mgr fail");
        return false;
    }
    if (wdMgr->linkHasPtk(uuid)) {
        return true;
    }
    return false;
}

bool IsAuthPreLinkNodeExist(uint32_t requestId)
{
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return false;
    }
    AuthPreLinkNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (item->requestId == requestId && item->connAddr.type == CONNECTION_ADDR_SESSION_WITH_KEY) {
            AuthPreLinkUnlock();
            return true;
        }
    }
    AuthPreLinkUnlock();
    return false;
}

bool AuthPreLinkCheckNeedPtk(uint32_t requestId, const char *uuid)
{
    return IsAuthPreLinkNodeExist(requestId) && !PreLinkCheckHasPtk(uuid);
}

int32_t AddToAuthPreLinkList(uint32_t requestId, int32_t fd, ConnectionAddr *connAddr)
{
    if (IsAuthPreLinkNodeExist(requestId)) {
        AUTH_LOGE(AUTH_CONN, "auth pre link exists");
        return SOFTBUS_ALREADY_EXISTED;
    }
    AuthPreLinkNode *item = (AuthPreLinkNode *)SoftBusCalloc(sizeof(AuthPreLinkNode));
    if (item == NULL) {
        AUTH_LOGE(AUTH_CONN, "item malloc fail");
        return SOFTBUS_MALLOC_ERR;
    }
    if (connAddr != NULL) {
        if (memcpy_s(&item->connAddr, sizeof(ConnectionAddr), connAddr, sizeof(ConnectionAddr)) != EOK) {
            AUTH_LOGE(AUTH_CONN, "copy connection addr failed");
        }
    }

    item->fd = fd;
    item->requestId = requestId;
    item->connAddr.type = CONNECTION_ADDR_SESSION_WITH_KEY;
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        SoftBusFree(item);
        return SOFTBUS_LOCK_ERR;
    }
    ListAdd(&g_authPreLinkList.list, &item->node);
    g_authPreLinkList.cnt++;
    AuthPreLinkUnlock();
    AUTH_LOGI(AUTH_CONN, "create new auth reuse key node, requestId=%{public}d, fd=%{public}u", requestId, fd);
    return SOFTBUS_OK;
}

int32_t FindAuthPreLinkNodeById(uint32_t requestId, AuthPreLinkNode *reuseNode)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(reuseNode != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "reuseNode is NULL");
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthPreLinkNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (item->requestId == requestId && item->connAddr.type == CONNECTION_ADDR_SESSION_WITH_KEY) {
            if (memcpy_s(reuseNode, sizeof(AuthPreLinkNode), item, sizeof(AuthPreLinkNode)) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy AuthPreLinkNode failed");
                AuthPreLinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            AuthPreLinkUnlock();
            return SOFTBUS_OK;
        }
    }
    AuthPreLinkUnlock();
    return SOFTBUS_NOT_FIND;
}

int32_t FindAuthPreLinkNodeByUuid(const char *uuid, AuthPreLinkNode *preLinkNode)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "uuid is NULL");
    AUTH_CHECK_AND_RETURN_RET_LOGE(preLinkNode != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "uuid is NULL");
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthPreLinkNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (memcmp(item->uuid, uuid, UUID_BUF_LEN) == 0) {
            if (memcpy_s(preLinkNode, sizeof(AuthPreLinkNode), item, sizeof(AuthPreLinkNode)) != EOK) {
                AUTH_LOGE(AUTH_CONN, "copy AuthPreLinkNode failed");
                AuthPreLinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            AuthPreLinkUnlock();
            return SOFTBUS_OK;
        }
    }
    AuthPreLinkUnlock();
    return SOFTBUS_NOT_FIND;
}

int32_t UpdateAuthPreLinkUuidById(uint32_t requestId, char *uuid)
{
    AUTH_CHECK_AND_RETURN_RET_LOGE(uuid != NULL, SOFTBUS_INVALID_PARAM, AUTH_CONN, "uuid is NULL");
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return SOFTBUS_LOCK_ERR;
    }
    AuthPreLinkNode *item = NULL;
    LIST_FOR_EACH_ENTRY(item, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (item->requestId == requestId && item->connAddr.type == CONNECTION_ADDR_SESSION_WITH_KEY) {
            if (memcpy_s(item->uuid, UUID_BUF_LEN, uuid, UUID_BUF_LEN) != EOK) {
                AUTH_LOGE(AUTH_CONN, "memcpy uuid failed");
                AuthPreLinkUnlock();
                return SOFTBUS_MEM_ERR;
            }
            AuthPreLinkUnlock();
            return SOFTBUS_OK;
        }
    }
    AuthPreLinkUnlock();
    return SOFTBUS_NOT_FIND;
}

void DelAuthPreLinkById(uint32_t requestId)
{
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return;
    }
    AuthPreLinkNode *item = NULL;
    AuthPreLinkNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (item->requestId == requestId) {
            ListDelete(&item->node);
            g_authPreLinkList.cnt--;
            SoftBusFree(item);
            AuthPreLinkUnlock();
            return;
        }
    }
    AuthPreLinkUnlock();
}

void DelAuthPreLinkByUuid(char *uuid)
{
    AUTH_CHECK_AND_RETURN_LOGE(uuid != NULL, AUTH_CONN, "uuid is NULL");
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return;
    }
    AuthPreLinkNode *item = NULL;
    AuthPreLinkNode *next = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        if (memcmp(item->uuid, uuid, UUID_BUF_LEN) == 0) {
            ListDelete(&item->node);
            g_authPreLinkList.cnt--;
            SoftBusFree(item);
            AuthPreLinkUnlock();
            return;
        }
    }
    AuthPreLinkUnlock();
}

void DeinitAuthPreLinkList(void)
{
    AuthPreLinkNode *item = NULL;
    AuthPreLinkNode *next = NULL;
    if (AuthPreLinkLock() != SOFTBUS_OK) {
        AUTH_LOGE(AUTH_CONN, "auth pre link lock fail");
        return;
    }
    LIST_FOR_EACH_ENTRY_SAFE(item, next, &g_authPreLinkList.list, AuthPreLinkNode, node) {
        ListDelete(&item->node);
        g_authPreLinkList.cnt--;
        SoftBusFree(item);
    }
    g_isInitAuthPreLinkList = false;
    AuthPreLinkUnlock();
    (void)SoftBusMutexDestroy(&g_authPreLinkList.lock);
}