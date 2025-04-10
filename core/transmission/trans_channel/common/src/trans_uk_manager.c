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

#include <securec.h>
#include <unistd.h>

#include "trans_uk_manager.h"
#include "bus_center_manager.h"
#include "lnn_distributed_net_ledger.h"
#include "lnn_ohos_account_adapter.h"
#include "softbus_access_token_adapter.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_session_account_adapter.h"
#include "trans_session_manager.h"

#define DEFAULT_ACCOUNT_UID  "ohosAnonymousUid"
static SoftBusList *g_ukRequestManagerList = NULL;

char *PackUkRequest(const AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return NULL;
    }

    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Cannot create cJSON object");
        return NULL;
    }
    char sourceUdid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, sourceUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get local udid failed, ret=%{public}d", ret);
        cJSON_Delete(json);
        return NULL;
    }
    int32_t userId = appInfo->myData.userId;
    uint32_t size = 0;
    char accountId[ACCOUNT_UID_LEN_MAX] = { 0 };
    ret = GetOsAccountUidByUserId(accountId, ACCOUNT_UID_LEN_MAX - 1, &size, userId);
    if (ret == SOFTBUS_NOT_LOGIN) {
        if (strcpy_s(accountId, ACCOUNT_UID_LEN_MAX - 1, DEFAULT_ACCOUNT_UID) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "strcpy_s default accountId failed");
        }
    }
    if (!AddStringToJsonObject(json, "SESSION_NAME", appInfo->peerData.sessionName) ||
        !AddStringToJsonObject(json, "SOURCE_UDID", sourceUdid) ||
        !AddNumberToJsonObject(json, "SOURCE_USER_ID", userId) ||
        !AddNumber64ToJsonObject(json, "SOURCE_TOKEN_ID", (int64_t)appInfo->callingTokenId) ||
        !AddStringToJsonObject(json, "SOURCE_ACCOUNT_ID", accountId)) {
        TRANS_LOGE(TRANS_CTRL, "add data to json failed");
        cJSON_Delete(json);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "json formatted failed");
    }
    cJSON_Delete(json);
    return data;
}

int32_t UnPackUkRequest(const cJSON *msg, AuthACLInfo *aclInfo, char *sessionName)
{
    if (msg == NULL || aclInfo == NULL || sessionName == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!GetJsonObjectStringItem(msg, "SESSION_NAME", sessionName, SESSION_NAME_SIZE_MAX) ||
        !GetJsonObjectStringItem(msg, "SOURCE_UDID", aclInfo->sourceUdid, UDID_BUF_LEN) ||
        !GetJsonObjectInt32Item(msg, "SOURCE_USER_ID", &(aclInfo->sourceUserId)) ||
        !GetJsonObjectNumber64Item(msg, "SOURCE_TOKEN_ID", (int64_t *)&(aclInfo->sourceTokenId)) ||
        !GetJsonObjectStringItem(msg, "SOURCE_ACCOUNT_ID", aclInfo->sourceAccountId, ACCOUNT_UID_LEN_MAX)) {
        TRANS_LOGE(TRANS_CTRL, "parse json data failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

char *PackUkReply(const AuthACLInfo *aclInfo, int32_t ukId)
{
    if (aclInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return NULL;
    }

    cJSON *json = cJSON_CreateObject();
    if (json == NULL) {
        TRANS_LOGE(TRANS_CTRL, "Cannot create cJSON object");
        return NULL;
    }
    if (!AddStringToJsonObject(json, "SOURCE_UDID", aclInfo->sourceUdid) ||
        !AddNumberToJsonObject(json, "SOURCE_USER_ID", aclInfo->sourceUserId) ||
        !AddNumber64ToJsonObject(json, "SOURCE_TOKEN_ID", (int64_t)aclInfo->sourceTokenId) ||
        !AddStringToJsonObject(json, "SOURCE_ACCOUNT_ID", aclInfo->sourceAccountId) ||
        !AddStringToJsonObject(json, "SINK_UDID", aclInfo->sinkUdid) ||
        !AddNumberToJsonObject(json, "SINK_USER_ID", aclInfo->sinkUserId) ||
        !AddNumber64ToJsonObject(json, "SINK_TOKEN_ID", (int64_t)aclInfo->sinkTokenId) ||
        !AddStringToJsonObject(json, "SINK_ACCOUNT_ID", aclInfo->sinkAccountId) ||
        !AddNumberToJsonObject(json, "SINK_UK_ID", ukId)) {
        TRANS_LOGE(TRANS_CTRL, "add data to json failed");
        cJSON_Delete(json);
        return NULL;
    }
    char *data = cJSON_PrintUnformatted(json);
    if (data == NULL) {
        TRANS_LOGE(TRANS_CTRL, "json formatted failed");
    }
    cJSON_Delete(json);
    return data;
}

int32_t UnPackUkReply(const cJSON *msg, AuthACLInfo *aclInfo, int32_t *ukId)
{
    if (msg == NULL || aclInfo == NULL || ukId == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    if (!GetJsonObjectStringItem(msg, "SOURCE_UDID", aclInfo->sourceUdid, UDID_BUF_LEN)  ||
        !GetJsonObjectStringItem(msg, "SOURCE_ACCOUNT_ID", aclInfo->sourceAccountId, ACCOUNT_UID_LEN_MAX) ||
        !GetJsonObjectInt32Item(msg, "SOURCE_USER_ID", &(aclInfo->sourceUserId)) ||
        !GetJsonObjectNumber64Item(msg, "SOURCE_TOKEN_ID", (int64_t *)&(aclInfo->sourceTokenId)) ||
        !GetJsonObjectStringItem(msg, "SINK_UDID", aclInfo->sinkUdid, UDID_BUF_LEN) ||
        !GetJsonObjectStringItem(msg, "SINK_ACCOUNT_ID", aclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX) ||
        !GetJsonObjectInt32Item(msg, "SINK_USER_ID", &(aclInfo->sinkUserId)) ||
        !GetJsonObjectNumber64Item(msg, "SINK_TOKEN_ID", (int64_t *)&(aclInfo->sinkTokenId)) ||
        !GetJsonObjectNumberItem(msg, "SINK_UK_ID", ukId)) {
        TRANS_LOGE(TRANS_CTRL, "parse json data failed");
        return SOFTBUS_PARSE_JSON_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransUkRequestMgrInit(void)
{
    if (g_ukRequestManagerList != NULL) {
        TRANS_LOGW(TRANS_INIT, "trans uk request manager list already inited.");
        return SOFTBUS_OK;
    }
    g_ukRequestManagerList = CreateSoftBusList();
    if (g_ukRequestManagerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans uk request manager init failed.");
        return SOFTBUS_MALLOC_ERR;
    }
    return SOFTBUS_OK;
}

void TransUkRequestMgrDeinit(void)
{
    if (g_ukRequestManagerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans uk manager list not init.");
        return;
    }
    if (SoftBusMutexLock(&g_ukRequestManagerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed");
        return;
    }
    UkRequestNode *requestNode = NULL;
    UkRequestNode *nextRequestNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestNode, nextRequestNode, &g_ukRequestManagerList->list, UkRequestNode, node) {
        ListDelete(&requestNode->node);
        SoftBusFree(requestNode);
    }
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    DestroySoftBusList(g_ukRequestManagerList);
    g_ukRequestManagerList = NULL;
    return;
}

static int32_t CopyACLInfo(AuthACLInfo *targetAclInfo, const AuthACLInfo *sourceAclInfo)
{
    targetAclInfo->sourceUserId = sourceAclInfo->sourceUserId;
    targetAclInfo->sourceTokenId = sourceAclInfo->sourceTokenId;
    targetAclInfo->sinkUserId = sourceAclInfo->sinkUserId;
    targetAclInfo->sinkTokenId = sourceAclInfo->sinkTokenId;
    if (strcpy_s(targetAclInfo->sourceUdid, UDID_BUF_LEN, sourceAclInfo->sourceUdid) != 0 ||
        strcpy_s(targetAclInfo->sinkUdid, UDID_BUF_LEN, sourceAclInfo->sinkUdid) != 0) {
        TRANS_LOGE(TRANS_CTRL, "strcpy udid failed");
        return SOFTBUS_STRCPY_ERR;
    }
    if (strcpy_s(targetAclInfo->sourceAccountId, ACCOUNT_UID_LEN_MAX, sourceAclInfo->sourceAccountId) != 0 ||
        strcpy_s(targetAclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX, sourceAclInfo->sinkAccountId) != 0) {
        TRANS_LOGE(TRANS_CTRL, "strcpy accountid failed");
        return SOFTBUS_STRCPY_ERR;
    }
    return SOFTBUS_OK;
}

int32_t TransUkRequestAddItem(
    uint32_t requestId, int32_t channelId, int32_t connId, int32_t pid, const AuthACLInfo *aclInfo)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_ukRequestManagerList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "uk request manager list not init.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(aclInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_ukRequestManagerList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_INIT, "lock failed");

    UkRequestNode *ukRequest = NULL;
    LIST_FOR_EACH_ENTRY(ukRequest, &(g_ukRequestManagerList->list), UkRequestNode, node) {
        if (ukRequest->requestId == requestId) {
            (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
            return SOFTBUS_ALREADY_EXISTED;
        }
    }

    UkRequestNode *newUkRequest = (UkRequestNode *)SoftBusCalloc(sizeof(UkRequestNode));
    if (newUkRequest == NULL) {
        TRANS_LOGE(TRANS_CTRL, "calloc failed");
        (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
        return SOFTBUS_MALLOC_ERR;
    }
    if (CopyACLInfo(&newUkRequest->aclInfo, aclInfo) != SOFTBUS_OK) {
        SoftBusFree(newUkRequest);
        (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
        return SOFTBUS_STRCPY_ERR;
    }

    newUkRequest->channelId = channelId;
    newUkRequest->connId = connId;
    newUkRequest->pid = pid;
    newUkRequest->requestId = requestId;
    ListInit(&newUkRequest->node);
    ListAdd(&g_ukRequestManagerList->list, &newUkRequest->node);
    g_ukRequestManagerList->cnt++;
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_OK;
}

int32_t TransUkRequestGetTcpInfoByRequestId(uint32_t requestId, AuthACLInfo *aclInfo, int32_t *channelId)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_ukRequestManagerList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "uk request manager list not init.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(aclInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_ukRequestManagerList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_INIT, "lock failed");

    UkRequestNode *ukRequest = NULL;
    LIST_FOR_EACH_ENTRY(ukRequest, &(g_ukRequestManagerList->list), UkRequestNode, node) {
        if (ukRequest->requestId == requestId) {
            if (CopyACLInfo(aclInfo, &ukRequest->aclInfo) != SOFTBUS_OK) {
                (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
                return SOFTBUS_STRCPY_ERR;
            }
            if (channelId != NULL) {
                *channelId = ukRequest->channelId;
            }
            (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUkRequestGetRequestInfoByRequestId(uint32_t requestId, UkRequestNode *ukRequest)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_ukRequestManagerList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "uk request manager list not init.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(ukRequest != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_ukRequestManagerList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_INIT, "lock failed");

    UkRequestNode *ukRequestNode = NULL;
    LIST_FOR_EACH_ENTRY(ukRequestNode, &(g_ukRequestManagerList->list), UkRequestNode, node) {
        if (ukRequestNode->requestId == requestId) {
            if (CopyACLInfo(&ukRequest->aclInfo, &ukRequestNode->aclInfo) != SOFTBUS_OK) {
                (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
                return SOFTBUS_STRCPY_ERR;
            }
            ukRequest->requestId = ukRequestNode->requestId;
            ukRequest->connId = ukRequestNode->connId;
            ukRequest->pid = ukRequestNode->pid;
            ukRequest->channelId = ukRequestNode->channelId;
            ukRequest->authHandle.authId = ukRequestNode->authHandle.authId;
            ukRequest->authHandle.type = ukRequestNode->authHandle.type;
            ukRequest->seq = ukRequestNode->seq;
            (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUkRequestSetAuthHandleAndSeq(uint32_t requestId, const AuthHandle *authHandle, uint64_t seq)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_ukRequestManagerList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "uk request manager list not init.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(authHandle != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        SoftBusMutexLock(&g_ukRequestManagerList->lock) == SOFTBUS_OK, SOFTBUS_LOCK_ERR, TRANS_INIT, "lock failed");
    UkRequestNode *ukRequestNode = NULL;
    LIST_FOR_EACH_ENTRY(ukRequestNode, &(g_ukRequestManagerList->list), UkRequestNode, node) {
        if (ukRequestNode->requestId == requestId) {
            ukRequestNode->authHandle.authId = authHandle->authId;
            ukRequestNode->authHandle.type = authHandle->type;
            ukRequestNode->seq = seq;
            (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_NOT_FIND;
}

int32_t TransUkRequestDeleteItem(uint32_t requestId)
{
    if (g_ukRequestManagerList == NULL) {
        TRANS_LOGE(TRANS_INIT, "trans uk manager list not init.");
        return SOFTBUS_NO_INIT;
    }
    if (SoftBusMutexLock(&g_ukRequestManagerList->lock) != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_INIT, "lock failed");
        return SOFTBUS_LOCK_ERR;
    }
    UkRequestNode *requestNode = NULL;
    UkRequestNode *nextRequestNode = NULL;
    LIST_FOR_EACH_ENTRY_SAFE(requestNode, nextRequestNode, &g_ukRequestManagerList->list, UkRequestNode, node) {
        if (requestNode->requestId == requestId) {
            ListDelete(&requestNode->node);
            SoftBusFree(requestNode);
            g_ukRequestManagerList->cnt--;
            (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
            return SOFTBUS_OK;
        }
    }
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_NOT_FIND;
}

int32_t GetUkPolicy(const AppInfo *appInfo)
{
#ifdef SOFTBUS_STANDARD_OS
    NodeInfo nodeInfo;
    (void)memset_s(&nodeInfo, sizeof(NodeInfo), 0, sizeof(NodeInfo));
    int32_t peerRet = LnnGetRemoteNodeInfoById(appInfo->peerNetWorkId, CATEGORY_NETWORK_ID, &nodeInfo);
    if (peerRet != SOFTBUS_OK || !nodeInfo.isSupportUkNego) {
        TRANS_LOGE(TRANS_CTRL, "get peer node info failed or peer node not support uk nego.");
        return NO_NEED_UK;
    }
    if (appInfo->myData.pid == getpid()) {
        // inner session not use uk
        return NO_NEED_UK;
    }
    int32_t accessTokenType = SoftBusGetAccessTokenType(appInfo->callingTokenId);
    if (accessTokenType == ACCESS_TOKEN_TYPE_NATIVE) {
        if (appInfo->myData.userId == INVALID_USER_ID) {
            return NO_NEED_UK;
        }
        return USE_NEGO_UK;
    }
    if (accessTokenType == ACCESS_TOKEN_TYPE_HAP) {
        return USE_NEGO_UK;
    }
    if (accessTokenType == ACCESS_TOKEN_TYPE_SHELL) {
        if (appInfo->myData.userId == INVALID_USER_ID) {
            return NO_NEED_UK;
        }
        return USE_NEGO_UK;
    }
    return NO_NEED_UK;
#else
    (void)appInfo;
    return NO_NEED_UK;
#endif
}

int32_t GetSourceAndSinkUdid(const char *peerNetWorkId, char *sourceUdid, char *sinkUdid)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(peerNetWorkId != NULL && sourceUdid != NULL && sinkUdid != NULL,
        SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");

    int32_t ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, sourceUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get source udid failed, ret=%{public}d", ret);
        return ret;
    }
    ret = LnnGetRemoteStrInfo(peerNetWorkId, STRING_KEY_DEV_UDID, sinkUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get sink udid failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
}

int32_t FillSinkAclInfo(const char *sessionName, AuthACLInfo *aclInfo, int32_t *pid)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        sessionName != NULL && aclInfo != NULL, SOFTBUS_INVALID_PARAM, TRANS_CTRL, "invalid param.");
    int32_t userId = INVALID_USER_ID;
    int32_t ret = TransGetAclInfoBySessionName(sessionName, (uint64_t *)&aclInfo->sinkTokenId, pid, &userId);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get tokenId and pid failed, ret=%{public}d", ret);
        return ret;
    }
    uint32_t size = 0;
    ret = GetOsAccountUidByUserId(aclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX - 1, &size, userId);
    if (ret == SOFTBUS_NOT_LOGIN) {
        if (strcpy_s(aclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX - 1, DEFAULT_ACCOUNT_UID) != EOK) {
            TRANS_LOGE(TRANS_CTRL, "strcpy_s default accountId failed");
        }
    }
    aclInfo->sinkUserId = userId;
    aclInfo->isServer = true;
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, aclInfo->sinkUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get sink udid failed, ret=%{public}d", ret);
        return ret;
    }
    return ret;
}

bool SpecialSaCanUseDeviceKey(uint64_t tokenId)
{
    return SoftBusSaCanUseDeviceKey(tokenId);
}

bool IsValidUkInfo(const UkIdInfo *ukIdInfo)
{
    return (ukIdInfo != NULL && ukIdInfo->myId != 0 && ukIdInfo->peerId != 0);
}