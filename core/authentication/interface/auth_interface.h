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

#ifndef AUTH_INTERFACE_H
#define AUTH_INTERFACE_H

#include <stdbool.h>
#include <stdint.h>

#include "softbus_conn_interface.h"

#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEVICE_KEY_LEN 64
#define AUTH_ERROR_CODE (-1)
#define AUTH_INVALID_ID (-1)

typedef enum {
    /* nearby type v1 */
    SOFT_BUS_OLD_V1 = 1,

    /* nearby type v2 */
    SOFT_BUS_OLD_V2 = 2,

    /* softbus type v1 */
    SOFT_BUS_NEW_V1 = 100,
} SoftBusVersion;

typedef enum {
    /* data type for device authentication */
    DATA_TYPE_AUTH = 0xFFFF0001,

    /* data type for synchronizing peer device information */
    DATA_TYPE_SYNC = 0xFFFF0002,

    /* data type for synchronizing peer device id */
    DATA_TYPE_DEVICE_ID = 0xFFFF0003,

    /* data type for connection */
    DATA_TYPE_CONNECTION = 0xFFFF0004,

    /* data type for closing ack */
    DATA_TYPE_CLOSE_ACK = 0xFFFF0005,
} AuthDataType;

typedef enum {
    /* reserved */
    NONE = 0,

    /* trust Engine, use plain text */
    TRUST_ENGINE = 1,

    /* hiChain, use plain text */
    HICHAIN = 2,

    /* authentication SDK, use plain text */
    AUTH_SDK = 3,

    /* hichain sync data, use plain text */
    HICHAIN_SYNC = 4,
} AuthDataModule;

typedef enum {
    CLIENT_SIDE_FLAG = 0,
    SERVER_SIDE_FLAG = 1,
    AUTH_SIDE_ANY,
} AuthSideFlag;

typedef enum {
    LNN = 0,
    BUSCENTER_MONITOR,
    VERIFY_P2P_DEVICE,
    VERIFY_MODULE_NUM
} AuthVerifyModule;

typedef enum {
    TRANS_UDP_DATA = 0,
    TRANS_AUTH_CHANNEL,
    TRANS_TIME_SYNC_CHANNEL,
    TRANS_P2P_MODULE,
    TRANS_P2P_LISTEN,
    TRANS_MODULE_NUM
} AuthTransModule;

typedef struct {
    uint8_t *buf;
    uint32_t bufLen;
    uint32_t outLen;
} OutBuf;

typedef struct {
    AuthDataType dataType;
    int32_t module;
    int64_t authId;
    int32_t flag;
    int64_t seq;
} AuthDataHead;

typedef struct {
    int32_t module;
    int32_t flags;
    int64_t seq;
    char *data;
    uint32_t len;
} AuthTransDataInfo;

typedef struct {
    void (*onKeyGenerated)(int64_t authId, ConnectOption *option, SoftBusVersion peerVersion);
    void (*onDeviceVerifyFail)(int64_t authId, int32_t reason);
    void (*onRecvSyncDeviceInfo)(int64_t authId, AuthSideFlag side, const char *peerUuid, uint8_t *data, uint32_t len);
    void (*onDeviceVerifyPass)(int64_t authId);
    void (*onDeviceNotTrusted)(const char *peerUdid);
    void (*onDisconnect)(int64_t authId);
    void (*onGroupCreated)(const char *groupId);
    void (*onGroupDeleted)(const char *groupId);
} VerifyCallback;

typedef struct {
    void (*onTransUdpDataRecv)(int64_t authId, const ConnectOption *option, const AuthTransDataInfo *info);
    void (*onAuthChannelClose)(int64_t authId);
} AuthTransCallback;

uint32_t AuthGetEncryptHeadLen(void);
int32_t AuthEncrypt(const ConnectOption *option, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf);
int32_t AuthDecrypt(const ConnectOption *option, AuthSideFlag side, uint8_t *data, uint32_t len, OutBuf *outbuf);
int32_t AuthEncryptBySeq(int32_t seq, AuthSideFlag *side, uint8_t *data, uint32_t len, OutBuf *outBuf);

int32_t OpenAuthServer(void);
void CloseAuthServer(void);
int32_t AuthRegCallback(AuthVerifyModule moduleId, VerifyCallback *cb);
int32_t AuthTransDataRegCallback(AuthTransModule moduleId, AuthTransCallback *cb);
void AuthTransDataUnRegCallback(AuthTransModule moduleId);

int64_t AuthVerifyDevice(AuthVerifyModule moduleId, const ConnectionAddr *addr);

int64_t AuthOpenChannel(const ConnectOption *option);
int32_t AuthPostData(const AuthDataHead *head, const uint8_t *data, uint32_t len);
int32_t AuthCloseChannel(int64_t authId);
int32_t AuthHandleLeaveLNN(int64_t authId);

int32_t AuthGetUuidByOption(const ConnectOption *option, char *buf, uint32_t bufLen);
int32_t AuthGetIdByOption(const ConnectOption *option, int64_t *authId);

int32_t AuthInit(void);
void AuthDeinit(void);

typedef enum {
    AUTH_LINK_TYPE_WIFI = 0,
    AUTH_LINK_TYPE_BR,
    AUTH_LINK_TYPE_BLE,
    AUTH_LINK_TYPE_P2P,
    AUTH_LINK_TYPE_MAX
} AuthLinkType;

typedef struct {
    AuthLinkType type;
    union {
        struct {
            char brMac[BT_MAC_LEN];
        } brInfo;
        struct {
            char bleMac[BT_MAC_LEN];
        } bleInfo;
        struct {
            char ip[IP_LEN];
            uint16_t port;
        } ipInfo;
    } info;
    char peerUid[MAX_ACCOUNT_HASH_LEN];
} AuthConnInfo;

/**
 * @brief Defines auth connection callbacks.
 */
typedef struct {
    /**
     * @brief Called when an auth connection is opened successfully.
     *
     * @param requestId indicates the open request.
     * @param authId id of auth connection.
     */
    void (*onConnOpened)(uint32_t requestId, int64_t authId);
    /**
     * @brief Called when an auth connection is opened failed.
     *
     * @param requestId indicates the open request.
     * @param reason error code.
     */
    void (*onConnOpenFailed)(uint32_t requestId, int32_t reason);
} AuthConnCallback;

typedef struct {
    AuthLinkType type; /* WIFI_WLAN and WIFI_P2P are supported. */
    union {
        struct {
            char ip[IP_STR_MAX_LEN];
            uint16_t port;
        } ipInfo;
    } info;
} AuthListennerInfo;

/**
 * @brief Start auth server listener, which identified by ip and port.
 *
 * @param info listener info {@link AuthListennerInfo}.
 * @return return SOFTBUS_OK if start successfully, otherwise return an error code.
 */
int32_t AuthStartListening(const AuthListennerInfo *info);

/**
 * @brief Stop auth server listener.
 *
 * @param info listener info {@link AuthListennerInfo}, only {@link type} is used.
 * @return return SOFTBUS_OK if stop successfully, otherwise return an error code.
 */
int32_t AuthStopListening(const AuthListennerInfo *info);

/**
 * @brief Initiate an auth connection open request, which is an asynchronous process.
 *
 * For WIFI_WLAN, just return the active auth connection.
 * For BR/BLE/WIFI_P2P, firstly establish a connection, and then do verify process.
 *
 * @param info auth connection info to special remote device {@link AuthConnInfo}.
 * @param requestId unique request id, which generated by {@link AuthGenRequestId}.
 * @param callback callback {@link AuthConnCallback} to receive open result, which cannot be empty.
 * @return return SOFTBUS_OK if request successfully, otherwise return an error code.
 */
int32_t AuthOpenConn(const AuthConnInfo *info, uint32_t requestId, const AuthConnCallback *callback);

/**
 * @brief Close an auth connection.
 *
 * @param authId id of auth connection.
 */
void AuthCloseConn(int64_t authId);

/**
 * @brief Generate an unique request id.
 *
 * @return return request id.
 */
uint32_t AuthGenRequestId(void);

/**
 * @brief Get auth connection info, which identified by auth id.
 *
 * @param authId id of auth connection.
 * @param info auth connection info {@link AuthConnInfo}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetConnInfo(int64_t authId, AuthConnInfo *info);

/**
 * @brief Get peer device uuid from auth connection, which identified by auth id.
 *
 * @param authId id of auth connection.
 * @param buf buffer to cache uuid.
 * @param size size of buffer {@link UUID_BUF_LEN}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetDeviceUuid(int64_t authId, char *buf, uint32_t size);

/**
 * @brief Get a preferred auth connection info for p2p lane, priority order: WiFi > BR > BLE.
 *
 * @param udid peer device uuid.
 * @param connInfo auth connection info {@link AuthConnInfo}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetPreferConnInfo(const char *uuid, AuthConnInfo *connInfo);

/**
 * @brief Set p2p mac address info.
 *
 * @param authId id of auth connection.
 * @param mac p2p mac address string.
 * @return return SOFTBUS_OK if set successfully, otherwise return an error code.
 */
int32_t AuthSetP2pMac(int64_t authId, const char *mac);

/**
 * @brief Get ConnectOption info by p2p mac.
 *
 * @param authId id of auth connection.
 * @param mac p2p mac address string.
 * @param option connect option info {@link ConnectOption}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetConnectOptionByP2pMac(const char *mac, AuthLinkType type, ConnectOption *option);

/**
 * @brief Get ConnectOption info by uuid and ConnectType.
 *
 * @param uuid device uuid string.
 * @param type connect type.
 * @param option connect option info {@link ConnectOption}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetActiveConnectOption(const char *uuid, ConnectType type, ConnectOption *option);

/**
 * @brief Get ble ConnectOption info by uuid.
 *
 * @param uuid device uuid string.
 * @param isServerSide client or server.
 * @param option connect option info {@link ConnectOption}.
 * @return return SOFTBUS_OK if get successfully, otherwise return an error code.
 */
int32_t AuthGetActiveBleConnectOption(const char *uuid, bool isServerSide, ConnectOption *option);

#ifdef __cplusplus
}
#endif
#endif
