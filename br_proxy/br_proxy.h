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
#ifndef BR_PROXY_H
#define BR_PROXY_H

#include "trans_log.h"
#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#define BR_MAC_LEN          33
#define UUID_LEN            38
#define ERR_DESC_STR_LEN    128

#define MAC_MIN_LENGTH 12             // 无分隔符格式最小长度
#define MAC_MAX_LENGTH 17             // 标准格式最大长度
#define MAC_SHA256_LEN 32             // MAC经SHA-256转换后长度
#define UUID_STD_LENGTH 36        // 标准格式UUID长度（含连字符）
#define UUID_NO_HYPHEN_LENGTH 32  // 无连字符UUID长度

typedef enum {
    CHANNEL_WAIT_RESUME = 0,
    CHANNEL_RESUME,
    CHANNEL_EXCEPTION_SOFTWARE_FAILED,
    CHANNEL_BR_NO_PAIRED,
} ChannelState;

typedef enum {
    LINK_BR = 0,
} TSLinkType;

// 对应 TypeScript 中的 ChannelInfo 接口
typedef struct {
    TSLinkType linktype;
    char peerBRMacAddr[BR_MAC_LEN];
    char peerBRUuid[UUID_LEN];
    int32_t recvPri;
    bool recvPriSet;  // 用于标记 recvPri 是否被设置
} BrProxyChannelInfo;

typedef enum {
    DATA_RECEIVE,
    CHANNEL_STATE,
    LISTENER_TYPE_MAX,
} ListenerType;

#define COMM_PKGNAME_BRPROXY "BrProxyPkgName"
#define PKGNAME_MAX_LEN  30
#define DEFAULT_CHANNEL_ID (-1)
#define BR_PROXY_SEND_MAX_LEN (4 * 1024 * 1024)
#define COMM_PKGNAME_PUSH "PUSH_SERVICE"

typedef struct {
    int32_t (*onChannelOpened)(int32_t sessionId, int32_t channelId, int32_t result);
    void (*onDataReceived)(int32_t channelId, const char *data, uint32_t dataLen);
    void (*onChannelStatusChanged)(int32_t channelId, int32_t state);
} IBrProxyListener;

typedef struct {
    int32_t (*queryPermission)(const char *bundleName, bool *isEmpowered);
} PermissonHookCb;

int32_t OpenBrProxy(int32_t sessionId, BrProxyChannelInfo *channelInfo, IBrProxyListener *listener);
int32_t CloseBrProxy(int32_t channelId);
int32_t SendBrProxyData(int32_t channelId, char* data, uint32_t dataLen);
int32_t SetListenerState(int32_t channelId, ListenerType type, bool isEnable);
bool IsProxyChannelEnabled(int32_t uid);
int32_t RegisterAccessHook(PermissonHookCb *cb);
void BrProxyServiceDeathNotify(void);

int32_t ClientTransOnBrProxyOpened(int32_t channelId, const char *brMac, const char *uuid, int32_t result);
int32_t ClientTransBrProxyDataReceived(int32_t channelId, const uint8_t *data, uint32_t len);
int32_t ClientTransBrProxyChannelChange(int32_t channelId, int32_t errCode);
int32_t ClientTransBrProxyQueryPermission(const char *bundleName, bool *isEmpowered);

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // BR_PROXY_H