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
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_json_utils.h"
#include "softbus_utils.h"
#include "trans_log.h"
#include "trans_session_manager.h"

static SoftBusList *g_ukRequestManagerList = NULL;

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

int32_t TransUkRequestAddItem(uint32_t requestId, int32_t channelId, int32_t channelType)
{
    TRANS_CHECK_AND_RETURN_RET_LOGE(
        g_ukRequestManagerList != NULL, SOFTBUS_NO_INIT, TRANS_INIT, "uk request manager list not init.");
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
    newUkRequest->channelId = channelId;
    newUkRequest->channelType = channelType;
    newUkRequest->requestId = requestId;
    ListInit(&newUkRequest->node);
    ListAdd(&g_ukRequestManagerList->list, &newUkRequest->node);
    g_ukRequestManagerList->cnt++;
    (void)SoftBusMutexUnlock(&g_ukRequestManagerList->lock);
    return SOFTBUS_OK;
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
            ukRequest->requestId = ukRequestNode->requestId;
            ukRequest->channelId = ukRequestNode->channelId;
            ukRequest->channelType = ukRequestNode->channelType;
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
    if (peerRet != SOFTBUS_OK || !IsSupportFeatureByCapaBit(nodeInfo.authCapacity, BIT_SUPPORT_USERKEY_NEGO)) {
        TRANS_LOGE(TRANS_CTRL, "get peer node info failed or peer node not support uk nego.");
        return NO_NEED_UK;
    }
    if (appInfo->myData.pid == getpid()) {
        // inner session not use uk
        return NO_NEED_UK;
    }
    if (appInfo->appType == APP_TYPE_AUTH || appInfo->appType == APP_TYPE_INNER) {
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

bool IsValidUkInfo(const UkIdInfo *ukIdInfo)
{
    return (ukIdInfo != NULL && ukIdInfo->myId != 0 && ukIdInfo->peerId != 0);
}

static int32_t FillSinkAclInfoByAppInfo(const AppInfo *appInfo, AuthACLInfo *aclInfo)
{
    if (appInfo == NULL || aclInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    aclInfo->isServer = true;
    aclInfo->sourceTokenId = appInfo->peerData.tokenId;
    aclInfo->sourceUserId = appInfo->peerData.userId;
    aclInfo->sinkTokenId = appInfo->myData.tokenId;
    aclInfo->sinkUserId = appInfo->myData.userId;
    if (strcpy_s(aclInfo->sourceAccountId, ACCOUNT_UID_LEN_MAX, appInfo->peerData.accountId) != EOK ||
        strcpy_s(aclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX, appInfo->myData.accountId) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "str copy accountid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    char peerUdid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(appInfo->peerNetWorkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get peer udid failed, ret=%{public}d", ret);
        return ret;
    }
    if (strcpy_s(aclInfo->sourceUdid, UDID_BUF_LEN, peerUdid) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "str copy peer udid fail.");
        return SOFTBUS_STRCPY_ERR;
    }
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, aclInfo->sinkUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get local udid failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t FillSourceAclInfoByAppInfo(const AppInfo *appInfo, AuthACLInfo *aclInfo)
{
    if (appInfo == NULL || aclInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    aclInfo->isServer = false;
    aclInfo->sourceTokenId = appInfo->myData.tokenId;
    aclInfo->sourceUserId = appInfo->myData.userId;
    aclInfo->sinkTokenId = appInfo->peerData.tokenId;
    aclInfo->sinkUserId = appInfo->peerData.userId;
    if (strcpy_s(aclInfo->sourceAccountId, ACCOUNT_UID_LEN_MAX, appInfo->myData.accountId) != EOK ||
        strcpy_s(aclInfo->sinkAccountId, ACCOUNT_UID_LEN_MAX, appInfo->peerData.accountId) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "str copy accountid failed.");
        return SOFTBUS_STRCPY_ERR;
    }
    char peerUdid[UDID_BUF_LEN] = { 0 };
    int32_t ret = LnnGetRemoteStrInfo(appInfo->peerNetWorkId, STRING_KEY_DEV_UDID, peerUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get peer udid failed, ret=%{public}d", ret);
        return ret;
    }
    if (strcpy_s(aclInfo->sinkUdid, UDID_BUF_LEN, peerUdid) != EOK) {
        TRANS_LOGE(TRANS_CTRL, "str copy peer udid failed.");
        return SOFTBUS_STRCPY_ERR;
    }
    ret = LnnGetLocalStrInfo(STRING_KEY_DEV_UDID, aclInfo->sourceUdid, UDID_BUF_LEN);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "get local udid failed, ret=%{public}d", ret);
        return ret;
    }
    return SOFTBUS_OK;
}

static int32_t TransGenUserkey(
    int32_t channelId, int32_t channelType, const AuthACLInfo *acl, AuthGenUkCallback *callback)
{
    uint32_t requestId = AuthGenRequestId();
    int32_t ret = SOFTBUS_OK;
    ret = TransUkRequestAddItem(requestId, channelId, channelType);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "add uk requset failed");
        return ret;
    }
    ret = AuthGenUkIdByAclInfo(acl, requestId, callback);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "gen uk failed");
        (void)TransUkRequestDeleteItem(requestId);
        return ret;
    }
    return ret;
}

int32_t GetUserkeyIdByAClInfo(
    const AppInfo *appInfo, int32_t channelId, int32_t channelType, int32_t *userKeyId, AuthGenUkCallback *callback)
{
    if (appInfo == NULL || userKeyId == NULL || callback == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    AuthACLInfo aclInfo = { 0 };
    int32_t ret = FillSinkAclInfoByAppInfo(appInfo, &aclInfo);
    if (ret != SOFTBUS_OK) {
        TRANS_LOGE(TRANS_CTRL, "fill sink ack info failed, ret=%{public}d", ret);
        return ret;
    }
    int32_t ukId = 0;
    ret = AuthFindUkIdByAclInfo(&aclInfo, &ukId);
    if (ret == SOFTBUS_AUTH_ACL_NOT_FOUND) {
        TRANS_LOGE(TRANS_CTRL, "find uk failed no acl, ret=%{public}d", ret);
        return ret;
    }
    if (ret != SOFTBUS_OK) {
        ret = TransGenUserkey(channelId, channelType, &aclInfo, callback);
        if (ret != SOFTBUS_OK) {
            TRANS_LOGE(TRANS_CTRL, "gen uk failed, ret=%{public}d", ret);
            return ret;
        }
        return SOFTBUS_TRANS_GEN_USER_KEY;
    }
    *userKeyId = ukId;
    return SOFTBUS_OK;
}

void FillHapSinkAclInfoToAppInfo(AppInfo *appInfo)
{
    if (appInfo == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return;
    }
    if (appInfo->myData.tokenType == ACCESS_TOKEN_TYPE_HAP) {
        (void)TransGetAclInfoBySessionName(
            appInfo->myData.sessionName, &appInfo->myData.tokenId, NULL, &appInfo->myData.userId);
        uint32_t size = 0;
        int32_t ret =
            GetOsAccountUidByUserId(appInfo->myData.accountId, ACCOUNT_UID_LEN_MAX - 1, &size, appInfo->myData.userId);
        if (ret != SOFTBUS_OK) {
            COMM_LOGE(COMM_SVC, "get current account failed. ret=%{public}d", ret);
        }
    }
}

int32_t EncryptAndAddSinkSessionKey(cJSON *msg, const AppInfo *appInfo)
{
    if (appInfo == NULL || msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetCapabilityBit(appInfo->channelCapability, TRANS_CHANNEL_SINK_GENERATE_KEY_OFFSET)) {
        if (GetCapabilityBit(appInfo->channelCapability, TRANS_CHANNEL_SINK_KEY_ENCRYPT_OFFSET)) {
            char encryptKey[ENCRYPT_KEY_LENGTH] = { 0 };
            uint32_t encryptSessionKeyLen = ENCRYPT_KEY_LENGTH;
            if (AuthEncryptByUkId(appInfo->myData.userKeyId, (uint8_t *)appInfo->sinkSessionKey, SESSION_KEY_LENGTH,
                (uint8_t *)encryptKey, &encryptSessionKeyLen) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "pack msg encrypt fail");
                return SOFTBUS_ENCRYPT_ERR;
            }
            char base64Encode[BASE64_ENCRYPT_KEY_LENGTH] = { 0 };
            size_t len = 0;
            if (SoftBusBase64Encode((unsigned char *)base64Encode, BASE64_ENCRYPT_KEY_LENGTH, &len,
                    (unsigned char *)encryptKey, sizeof(encryptKey)) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Failed to encode sink session key");
                return SOFTBUS_CREATE_JSON_ERR;
            }
            if (!AddStringToJsonObject(msg, "SESSION_KEY", base64Encode)) {
                TRANS_LOGE(TRANS_CTRL, "Failed to add sink session key");
                return SOFTBUS_CREATE_JSON_ERR;
            }
            return SOFTBUS_OK;
        } else {
            char base64Encode[BASE64_SESSION_KEY_LEN] = { 0 };
            size_t len = 0;
            if (SoftBusBase64Encode((unsigned char *)base64Encode, BASE64_SESSION_KEY_LEN, &len,
                    (unsigned char *)appInfo->sinkSessionKey, sizeof(appInfo->sinkSessionKey)) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Failed to encode sink session key");
                return SOFTBUS_CREATE_JSON_ERR;
            }
            if (!AddStringToJsonObject(msg, "SESSION_KEY", base64Encode)) {
                TRANS_LOGE(TRANS_CTRL, "Failed to add sink session key");
                return SOFTBUS_CREATE_JSON_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}

int32_t DecryptAndAddSinkSessionKey(const cJSON *msg, AppInfo *appInfo)
{
    if (appInfo == NULL || msg == NULL) {
        TRANS_LOGE(TRANS_CTRL, "invalid param.");
        return SOFTBUS_INVALID_PARAM;
    }
    if (GetCapabilityBit(appInfo->channelCapability, TRANS_CHANNEL_SINK_GENERATE_KEY_OFFSET)) {
        if (GetCapabilityBit(appInfo->channelCapability, TRANS_CHANNEL_SINK_KEY_ENCRYPT_OFFSET)) {
            char encodeEncryptKey[BASE64_ENCRYPT_KEY_LENGTH] = { 0 };
            if (!GetJsonObjectStringItem(msg, "SESSION_KEY", encodeEncryptKey, BASE64_ENCRYPT_KEY_LENGTH)) {
                TRANS_LOGE(TRANS_CTRL, "Failed to get sink session key");
                return SOFTBUS_PARSE_JSON_ERR;
            }
            AuthACLInfo aclInfo = { 0 };
            int32_t ret = FillSourceAclInfoByAppInfo(appInfo, &aclInfo);
            if (ret != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "fill source acl info failed, ret=%{public}d", ret);
                return ret;
            }
            ret = AuthFindUkIdByAclInfo(&aclInfo, &appInfo->myData.userKeyId);
            TRANS_CHECK_AND_RETURN_RET_LOGE(ret == SOFTBUS_OK, ret, TRANS_CTRL, "find uk failed, ret=%{public}d", ret);
            char decodeEncryptKey[ENCRYPT_KEY_LENGTH] = { 0 };
            size_t len = 0;
            if (SoftBusBase64Decode((unsigned char *)decodeEncryptKey, ENCRYPT_KEY_LENGTH, &len,
                    (unsigned char *)encodeEncryptKey, strlen(encodeEncryptKey)) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Failed to decode sink session key");
                return SOFTBUS_PARSE_JSON_ERR;
            }
            uint32_t decDataLen = SESSION_KEY_LENGTH;
            if (AuthDecryptByUkId(appInfo->myData.userKeyId, (uint8_t *)decodeEncryptKey, ENCRYPT_KEY_LENGTH,
                (uint8_t *)appInfo->sinkSessionKey, &decDataLen) != SOFTBUS_OK) {
                TRANS_LOGE(
                    TRANS_CTRL, "srv process recv data: decrypt failed. ukid=%{public}d", appInfo->myData.userKeyId);
                return SOFTBUS_DECRYPT_ERR;
            }
            return SOFTBUS_OK;
        } else {
            char encodeEncryptKey[BASE64_SESSION_KEY_LEN] = { 0 };
            (void)GetJsonObjectStringItem(msg, "SESSION_KEY", encodeEncryptKey, BASE64_SESSION_KEY_LEN);
            size_t len = 0;
            if (SoftBusBase64Decode((unsigned char *)appInfo->sinkSessionKey, sizeof(appInfo->sinkSessionKey), &len,
                    (unsigned char *)encodeEncryptKey, strlen(encodeEncryptKey)) != SOFTBUS_OK) {
                TRANS_LOGE(TRANS_CTRL, "Failed to decode sink session key");
                return SOFTBUS_PARSE_JSON_ERR;
            }
            return SOFTBUS_OK;
        }
    }
    return SOFTBUS_OK;
}