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

#include <unistd.h>

#include "cJSON.h"

#include "p2plink_common.h"
#include "p2plink_device.h"
#include "p2plink_message.h"
#include "p2plink_reference.h"

#include "securec.h"
#include "softbus_def.h"
#include "softbus_errcode.h"
#include "softbus_json_utils.h"
#include "softbus_log.h"

NO_SANITIZE("cfi") char* P2pLinkPackReuseRequest(const char *mac)
{
    char *buf = NULL;
    cJSON *root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }
    if (!AddNumberToJsonObject(root, KEY_COMMAND_TYPE, CMD_REUSE) ||
        !AddStringToJsonObject(root, KEY_MAC, mac)) {
        cJSON_Delete(root);
        return NULL;
    }
    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

static int32_t P2pLinkUnPackReuseRequest(const cJSON *root, char *mac, uint32_t len)
{
    if (!GetJsonObjectStringItem(root, KEY_MAC, mac, len)) {
        CLOGE("Failed to UnPackReuseRequest msg mac");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") char* P2pLinkPackReuseResponse(const char *mac, int result)
{
    char *buf = NULL;
    cJSON *root = NULL;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddNumberToJsonObject(root, KEY_COMMAND_TYPE, CMD_REUSE_RESPONSE) ||
        !AddNumberToJsonObject(root, KEY_RESULT, result) ||
        !AddStringToJsonObject(root, KEY_MAC, mac)) {
        cJSON_Delete(root);
        return NULL;
    }

    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

static int32_t P2pLinkUnPackReuseResponse(const cJSON *root, char *mac, uint32_t len, int32_t *result)
{
    if (!GetJsonObjectInt32Item(root, KEY_RESULT, result) ||
        !GetJsonObjectStringItem(root, KEY_MAC, mac, len)) {
        CLOGE("Failed to get  P2pLinkUnPackReuseResponse");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") char* P2pLinkPackDisconnectCmd(const char *mac)
{
    char *buf = NULL;
    cJSON *root = NULL;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddNumberToJsonObject(root, KEY_COMMAND_TYPE, CMD_DISCONNECT_COMMAND) ||
        !AddStringToJsonObject(root, KEY_MAC, mac)) {
        cJSON_Delete(root);
        return NULL;
    }
    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

static int32_t P2pLinkUnPackDisconnectCmd(const cJSON *root, char *mac, uint32_t len)
{
    if (!GetJsonObjectStringItem(root, KEY_MAC, mac, len)) {
        CLOGE("Failed to get  P2pLinkUnPackDisconnectCmd");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") char* P2pLinkPackHandshake(const char *mac, const char *ip)
{
    char *buf = NULL;
    cJSON *root = NULL;

    root = cJSON_CreateObject();
    if (root == NULL) {
        return NULL;
    }

    if (!AddNumberToJsonObject(root, KEY_COMMAND_TYPE, CMD_CTRL_CHL_HANDSHAKE) ||
        !AddStringToJsonObject(root, KEY_MAC, mac) ||
        !AddStringToJsonObject(root, KEY_IP, ip)) {
        cJSON_Delete(root);
        return NULL;
    }
    buf = cJSON_PrintUnformatted(root);
    cJSON_Delete(root);
    return buf;
}

static int32_t P2pLinkUnPackHandshake(const cJSON *root, char *mac, uint32_t macLen, char *ip, uint32_t ipLen)
{
    if (!GetJsonObjectStringItem(root, KEY_MAC, mac, macLen)) {
        CLOGE("Failed to get P2pLinkUnPackHandshake");
        return SOFTBUS_ERR;
    }
    if (!GetJsonObjectStringItem(root, KEY_IP, ip, ipLen)) {
        CLOGE("P2pLinkUnPackHandshake：get IP Failed");
    }
    return SOFTBUS_OK;
}

static int32_t P2pLinkUnPackWifiCfg(const cJSON *root, char *wificfg, uint32_t len)
{
    if (!GetJsonObjectStringItem(root, KEY_SELF_WIFI_CONFIG, wificfg, len)) {
        CLOGE("Failed to get  P2pLinkUnPackWifiCfg");
        return SOFTBUS_ERR;
    }
    return SOFTBUS_OK;
}

static int64_t GetPreferenceAuthId(const P2pLinkAuthId *chan)
{
    CLOGI("auth status %d p2pid %" PRId64 ", authid %" PRId64, chan->p2pAuthIdState, chan->p2pAuthId, chan->inAuthId);
    if (chan->p2pAuthIdState == P2PLINK_AUTHCHAN_FINISH) {
        return chan->p2pAuthId;
    } else {
        return chan->inAuthId;
    }
}

NO_SANITIZE("cfi") int32_t P2pLinkSendHandshake(const P2pLinkAuthId *chan, const char *myMac, const char *myIp)
{
    char *buf = NULL;
    int32_t ret;
    int64_t authId;

    authId = GetPreferenceAuthId(chan);
    buf = P2pLinkPackHandshake(myMac, myIp);
    if (buf == NULL) {
        CLOGE("pack handshake fail");
        return SOFTBUS_ERR;
    }
    ret = P2pLinkSendMessage(authId, buf, strlen(buf) + 1);
    if (ret != SOFTBUS_OK) {
        CLOGE("send handshake msg fail");
        cJSON_free(buf);
        return SOFTBUS_ERR;
    }
    cJSON_free(buf);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t P2pLinkSendDisConnect(const P2pLinkAuthId *chan, const char *myMac)
{
#define DISCONNECT_DELAY_100MS   100000
    char *buf = NULL;
    int32_t ret;
    int64_t authId;

    authId = GetPreferenceAuthId(chan);
    buf = P2pLinkPackDisconnectCmd(myMac);
    if (buf == NULL) {
        CLOGE("pack disconnect fail");
        return SOFTBUS_ERR;
    }
    ret = P2pLinkSendMessage(authId, buf, strlen(buf) + 1);
    if (ret != SOFTBUS_OK) {
        CLOGE("send disconnect msg fail");
        cJSON_free(buf);
        return SOFTBUS_ERR;
    }
    cJSON_free(buf);
    usleep(DISCONNECT_DELAY_100MS);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t P2pLinkSendReuse(const P2pLinkAuthId *chan, const char *myMac)
{
    char *buf = NULL;
    int32_t ret;
    int64_t authId;

    authId = GetPreferenceAuthId(chan);
    buf = P2pLinkPackReuseRequest(myMac);
    if (buf == NULL) {
        CLOGE("pack reuse fail");
        return SOFTBUS_ERR;
    }
    ret = P2pLinkSendMessage(authId, buf, strlen(buf) + 1);
    if (ret != SOFTBUS_OK) {
        CLOGE("send reuse msg fail");
        cJSON_free(buf);
        return SOFTBUS_ERR;
    }
    cJSON_free(buf);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") int32_t P2pLinkSendReuseResponse(const P2pLinkAuthId *chan, const char *myMac, int32_t res)
{
    char *buf = NULL;
    int32_t ret;
    int64_t authId;

    authId = GetPreferenceAuthId(chan);
    buf = P2pLinkPackReuseResponse(myMac, res);
    if (buf == NULL) {
        CLOGE("pack reuse  Responsefail");
        return SOFTBUS_ERR;
    }
    ret = P2pLinkSendMessage(authId, buf, strlen(buf) + 1);
    if (ret != SOFTBUS_OK) {
        CLOGE("send reuse response msg fail");
        cJSON_free(buf);
        return SOFTBUS_ERR;
    }
    cJSON_free(buf);
    return SOFTBUS_OK;
}

NO_SANITIZE("cfi") void P2pLinkHandleHandshake(int64_t authId, int32_t seq, const cJSON *root)
{
    char mac[P2P_MAC_LEN] = {0};
    char ip[P2P_IP_LEN] = {0};
    ConnectedNode *connedDev = NULL;

    CLOGI("recv handshake authid %" PRId64 ", seq %d", authId, seq);
    if (P2pLinkUnPackHandshake(root, mac, sizeof(mac), ip, sizeof(ip)) != SOFTBUS_OK) {
        CLOGE("unpack handshake fail");
        return;
    }
    connedDev = P2pLinkGetConnedDevByMac(mac);
    if (connedDev == NULL) {
        CLOGE("handshake can not find dev");
        return;
    }
    CLOGI("handshake rec authid %" PRId64, authId);
    connedDev->chanId.p2pAuthId = authId;
    connedDev->chanId.p2pAuthIdState = P2PLINK_AUTHCHAN_FINISH;
}

NO_SANITIZE("cfi") void P2pLinkHandleReuseResponse(int64_t authId, int32_t seq, const cJSON *root)
{
    char peerMac[P2P_MAC_LEN] = {0};
    int32_t respRet = 0;
    ConnectingNode *conningItem = NULL;
    ConnectedNode *connedDev = NULL;

    CLOGI("recv ReuseResponse authid %" PRIu64 ", seq %d", authId, seq);
    if (P2pLinkUnPackReuseResponse(root, peerMac, sizeof(peerMac), &respRet) != SOFTBUS_OK) {
        CLOGE("unpack ReuseResponse fail");
        return;
    }
    conningItem = P2pLinkGetConningByPeerMacState(peerMac, P2PLINK_MANAGER_STATE_REUSE);
    if (conningItem == NULL) {
        CLOGE("ReuseResponse can not find dev mac");
        return;
    }

    if (respRet != P2PLINK_OK) {
        CLOGE("ReuseResponse fail %d ", respRet);
        P2pLinkConningCallback(conningItem, SOFTBUS_ERR, respRet);
        P2pLinkDelConning(conningItem->connInfo.requestId);
        return;
    }
    connedDev = P2pLinkGetConnedDevByMac(peerMac);
    if (connedDev == NULL) {
        CLOGE("reuse dev is offline ");
        P2pLinkConningCallback(conningItem, SOFTBUS_ERR, ERROR_REUSE_FAILED);
        P2pLinkDelConning(conningItem->connInfo.requestId);
        return;
    }
    if ((strcpy_s(conningItem->myIp, sizeof(conningItem->myIp), P2pLinkGetMyIp()) != EOK) ||
        (strcpy_s(conningItem->peerIp, sizeof(conningItem->peerIp), connedDev->peerIp) != EOK)) {
        CLOGE("strcpy error ");
    }

    if (P2pLinkSharelinkReuse() != SOFTBUS_OK) {
        CLOGE("reuse link failed: invoke P2pLinkSharelinkReuse failed.");
        P2pLinkConningCallback(conningItem, SOFTBUS_ERR, ERROR_REUSE_FAILED);
        P2pLinkDelConning(conningItem->connInfo.requestId);
        return;
    }

    P2pLinkConningCallback(conningItem, SOFTBUS_OK, 0);
    P2pLinkAddPidMacRef(conningItem->connInfo.pid, peerMac);
    P2pLinkAddMyP2pRef();
    P2pLinkDelConning(conningItem->connInfo.requestId);
    P2pLinkDumpRef();
}

NO_SANITIZE("cfi") void P2pLinkHandleReuseRequest(int64_t authId, int32_t seq, const cJSON *root)
{
    char peerMac[P2P_MAC_LEN] = {0};
    int32_t respRet;
    ConnectedNode *item = NULL;
    P2pLinkRole myRole = P2pLinkGetRole();
    P2pLinkAuthId linkAuthId = {0};
    linkAuthId.inAuthId = authId;

    CLOGI("recv ReuseRequest authid %" PRIu64 ", seq %d", authId, seq);
    if (P2pLinkUnPackReuseRequest(root, peerMac, sizeof(peerMac)) != SOFTBUS_OK) {
        CLOGE("unpack ReuseResponse fail");
        return;
    }
    CLOGI("recv peer reuse request");
    if (myRole == ROLE_GC) {
        if (P2pLinkConnedIsEmpty() == SOFTBUS_OK) {
            CLOGE("used by others");
            respRet = ERROR_LINK_USED_BY_ANOTHER_SERVICE;
            (void)P2pLinkSendReuseResponse(&linkAuthId, P2pLinkGetMyMac(), respRet);
            return;
        } else {
            item = P2pLinkGetConnedDevByMac(peerMac);
            if (item == NULL) {
                CLOGE("peer dev not onliee");
                respRet = ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE;
                (void)P2pLinkSendReuseResponse(&linkAuthId, P2pLinkGetMyMac(), respRet);
                return;
            }
        }
    }

    item = P2pLinkGetConnedDevByMac(peerMac);
    if (item == NULL) {
        CLOGE("role is go, peer dev not onliee");
        respRet = ERROR_REUSE_FAILED;
        (void)P2pLinkSendReuseResponse(&linkAuthId, P2pLinkGetMyMac(), respRet);
        return;
    }
    if (P2pLinkSharelinkReuse() == SOFTBUS_OK) {
        respRet = P2PLINK_OK;
        P2pLinkAddMyP2pRef();
        CLOGE("share reuse ok");
        (void)P2pLinkSendReuseResponse(&linkAuthId, P2pLinkGetMyMac(), respRet);
        P2pLinkDumpRef();
    } else {
        CLOGE("share reuse fail");
        respRet = ERROR_REUSE_FAILED;
        (void)P2pLinkSendReuseResponse(&linkAuthId, P2pLinkGetMyMac(), respRet);
    }
}
NO_SANITIZE("cfi") void P2pLinkHandleDisconnectCmd(int64_t authId, int32_t seq, const cJSON *root)
{
    P2pLinkRole myRole = P2pLinkGetRole();
    int32_t myRef = P2pLinkGetMyP2pRef();
    int32_t ret;
    char peerMac[P2P_MAC_LEN] = {0};
    ConnectedNode *connedDev = NULL;

    (void)seq;
    (void)authId;
    if (myRole == ROLE_NONE || myRef <= 0) {
        CLOGE("already disconnected.");
        return;
    }

    ret = P2pLinkUnPackDisconnectCmd(root, peerMac, sizeof(peerMac));
    if (ret != SOFTBUS_OK) {
        CLOGE("UnPackDisconnectCmd: onFailure ret %d", ret);
        return;
    }

    connedDev = P2pLinkGetConnedDevByMac(peerMac);
    if (connedDev == NULL) {
        CLOGE("peer dev not online");
        return;
    }

    ret = P2pLinkSharelinkRemoveGroup();
    if (ret != SOFTBUS_OK) {
        CLOGE("sharelinkRemoveGroup: onFailure ret %d", ret);
        return;
    }
    P2pLinkDelMyP2pRef();
    P2pLinkDumpRef();
    CLOGI("handle disconnect ok");
}

NO_SANITIZE("cfi") void P2pLinkHandleWifiCfg(int64_t authId, int32_t seq, const cJSON *root)
{
    char wifiCfg[P2PLINK_WIFICFG_LEN] = {0};
    int32_t ret;

    (void)seq;
    (void)authId;
    ret = P2pLinkUnPackWifiCfg(root, wifiCfg, sizeof(wifiCfg));
    if (ret != SOFTBUS_OK) {
        CLOGE("P2pLinkUnPackWifiCfg fail");
        return;
    }
    ret = P2pLinkSetPeerWifiCfgInfo(wifiCfg);
    if (ret != SOFTBUS_OK) {
        CLOGE("P2pLinkSetPeerWifiCfgInfo fail %d", ret);
    }
}

NO_SANITIZE("cfi") void P2pLinkControlMsgProc(int64_t authId, int64_t seq, P2pLinkCmdType type, const cJSON *root)
{
    CLOGI("recv control msgtype %d", type);
    if (P2pLinkIsEnable() == false) {
        CLOGI("in controlling p2p state is closed");
        return;
    }
    switch (type) {
        case CMD_CTRL_CHL_HANDSHAKE:
            P2pLinkHandleHandshake(authId, seq, root);
            break;
        case CMD_REUSE_RESPONSE:
            P2pLinkHandleReuseResponse(authId, seq, root);
            break;
        case CMD_REUSE:
            P2pLinkHandleReuseRequest(authId, seq, root);
            break;
        case CMD_DISCONNECT_COMMAND:
            P2pLinkHandleDisconnectCmd(authId, seq, root);
            break;
        case CMD_GC_WIFI_CONFIG_STATE_CHANGE:
            P2pLinkHandleWifiCfg(authId, seq, root);
            break;
        default:
            break;
    }
}

NO_SANITIZE("cfi") void P2pLinkonAuthChannelClose(int64_t authId)
{
    CLOGI("recv authid %" PRId64 " close", authId);
    P2pLinkDelConnedByAuthId(authId);
    if (P2pLinkConnedIsEmpty() == SOFTBUS_OK) {
        CLOGI("all dev is offline, clean p2p ref");
        P2pLinkMyP2pRefClean();
    }
}