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

#include "softbus_proxychannel_network.h"

#include <securec.h>
#include "softbus_adapter_crypto.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_log.h"
#include "softbus_proxychannel_manager.h"
#include "softbus_transmission_interface.h"

#define MAX_LISTENER_CNT 2

typedef struct {
    char sessionName[SESSION_NAME_SIZE_MAX];
    INetworkingListener listener;
} INetworkingListenerEntry;

static INetworkingListenerEntry g_listeners[MAX_LISTENER_CNT] = { 0 };

static INetworkingListenerEntry *FindListenerEntry(const char *sessionName)
{
    for (int32_t i = 0; i < SESSION_NAME_SIZE_MAX; i++) {
        if (strcmp(sessionName, g_listeners[i].sessionName) == 0) {
            return &g_listeners[i];
        }
    }
    return NULL;
}

NO_SANITIZE("cfi")
int32_t NotifyNetworkingChannelOpened(
    const char *sessionName, int32_t channelId, const AppInfo *appInfo, unsigned char isServer)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelOpened == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "net onChannelOpened is null");
        return SOFTBUS_ERR;
    }

    if (entry->listener.onChannelOpened(channelId, appInfo->peerData.deviceId, isServer) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "notify channel open fail");
        return SOFTBUS_ERR;
    }

    return SOFTBUS_OK;
}

NO_SANITIZE("cfi")
void NotifyNetworkingChannelOpenFailed(const char *sessionName, int32_t channelId, const char *networkId)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelOpenFailed == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "net onChannelOpenFailed is null");
        return;
    }
    entry->listener.onChannelOpenFailed(channelId, networkId);
}

NO_SANITIZE("cfi") void NotifyNetworkingChannelClosed(const char *sessionName, int32_t channelId)
{
    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onChannelClosed == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "net onChannelClosed is null");
        return;
    }
    entry->listener.onChannelClosed(channelId);
}

static int32_t TransNotifyDecryptNetworkingMsg(const char *sessionKey,
    const char *in, uint32_t inLen, char *out, uint32_t *outLen)
{
    AesGcmCipherKey cipherKey = {0};
    cipherKey.keyLen = SESSION_KEY_LENGTH; // 256 bit encryption
    if (memcpy_s(cipherKey.key, SESSION_KEY_LENGTH, sessionKey, SESSION_KEY_LENGTH) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "memcpy key error.");
        return SOFTBUS_ERR;
    }
    int32_t ret = SoftBusDecryptData(&cipherKey, (unsigned char*)in, inLen, (unsigned char*)out, outLen);
    (void)memset_s(&cipherKey, sizeof(AesGcmCipherKey), 0, sizeof(AesGcmCipherKey));
    if (ret != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "SoftBusDecryptData fail(=%d).", ret);
        return SOFTBUS_DECRYPT_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi")
void NotifyNetworkingMsgReceived(const char *sessionName, int32_t channelId, const char *data, uint32_t len)
{
    if (sessionName == NULL || data == NULL || len <= OVERHEAD_LEN)  {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "invalid param channelid[%d] len[%u]", channelId, len);
        return;
    }

    char sessionKey[SESSION_KEY_LENGTH] = {0};
    uint32_t sessionKeySize = SESSION_KEY_LENGTH;
    if (TransProxyGetSessionKeyByChanId(channelId, sessionKey, sessionKeySize) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "get sessionkey fail channelid[%d]", channelId);
        return;
    }

    uint32_t outDataLen = len - OVERHEAD_LEN;
    char *outData = (char *)SoftBusCalloc(outDataLen);
    if (outData == NULL) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "malloc len[%u] fail", outDataLen);
        return;
    }
    if (TransNotifyDecryptNetworkingMsg(sessionKey, data, len, outData, &outDataLen) != SOFTBUS_OK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "decrypt msg fail channelid[%d]", channelId);
        SoftBusFree(outData);
        return;
    }

    INetworkingListenerEntry *entry = FindListenerEntry(sessionName);
    if (entry == NULL || entry->listener.onMessageReceived == NULL) {
        SoftBusFree(outData);
        return;
    }
    entry->listener.onMessageReceived(channelId, outData, outDataLen);
    SoftBusFree(outData);
}

NO_SANITIZE("cfi")
int TransRegisterNetworkingChannelListener(const char *sessionName, const INetworkingListener *listener)
{
    int32_t unuse = -1;
    for (int32_t i = 0; i < MAX_LISTENER_CNT; i++) {
        if (strlen(g_listeners[i].sessionName) == 0) {
            unuse = i;
            break;
        }
        if (strcmp(sessionName, g_listeners[i].sessionName) == 0) {
            return SOFTBUS_OK;
        }
    }
    if (unuse == -1) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "exceed %d listener registered", MAX_LISTENER_CNT);
        return SOFTBUS_ERR;
    }

    if (strcpy_s(g_listeners[unuse].sessionName, SESSION_NAME_SIZE_MAX, sessionName) != EOK) {
        SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_ERROR, "strcpy_s session name failed");
        return SOFTBUS_ERR;
    }
    g_listeners[unuse].listener = *listener;
    SoftBusLog(SOFTBUS_LOG_TRAN, SOFTBUS_LOG_INFO, "register net listener ok");
    return SOFTBUS_OK;
}
