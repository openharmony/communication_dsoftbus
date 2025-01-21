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

#ifndef SOFTBUS_CONN_INTERFACE_H
#define SOFTBUS_CONN_INTERFACE_H
#include <stdint.h>

#include "softbus_common.h"
#include "softbus_def.h"
#include "softbus_protocol_def.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif
typedef enum {
    MODULE_TRUST_ENGINE = 1,
    MODULE_HICHAIN = 2,
    MODULE_AUTH_SDK = 3,
    MODULE_AUTH_CONNECTION = 5,
    MODULE_AUTH_CANCEL = 6,
    MODULE_MESSAGE_SERVICE = 8,
    MODULE_AUTH_CHANNEL = 8,
    MODULE_AUTH_MSG = 9,
    MODULE_BLUETOOTH_MANAGER = 9,
    MODULE_CONNECTION = 11,
    MODULE_DIRECT_CHANNEL = 12,
    MODULE_PROXY_CHANNEL = 13,
    MODULE_DEVICE_AUTH = 14,
    MODULE_P2P_LINK = 15,
    MODULE_P2P_LISTEN = 16,
    MODULE_UDP_INFO = 17,
    MODULE_P2P_NETWORKING_SYNC = 18,
    MODULE_TIME_SYNC = 19,
    MODULE_PKG_VERIFY = 20,
    MODULE_META_AUTH = 21,
    MODULE_P2P_NEGO = 22,
    MODULE_AUTH_SYNC_INFO = 23,
    MODULE_PTK_VERIFY = 24,
    MODULE_SESSION_AUTH = 25,
    MODULE_BLE_NET = 100,
    MODULE_BLE_CONN = 101,
    MODULE_NIP_BR_CHANNEL = 201,
    MODULE_OLD_NEARBY = 300,
} ConnModule;

typedef enum {
    CONNECT_TCP = 1,
    CONNECT_BR,
    CONNECT_BLE,
    CONNECT_P2P,
    CONNECT_P2P_REUSE,
    CONNECT_BLE_DIRECT,
    CONNECT_HML,
    CONNECT_TRIGGER_HML,
    CONNECT_TYPE_MAX
} ConnectType;

#define CONN_INVALID_LISTENER_MODULE_ID    0xffff
#define CONN_DYNAMIC_LISTENER_MODULE_COUNT 32
#define DEVID_BUFF_LEN                     65
#define NETIF_NAME_LEN                     16

#define BT_LINK_TYPE_BR  1
#define BT_LINK_TYPE_BLE 2
#define HML_NUM 8
#define AUTH_ENHANCED_P2P_NUM 8

typedef enum {
    PROXY = 0,
    AUTH,
    AUTH_P2P,
    AUTH_ENHANCED_P2P_START,
    AUTH_ENHANCED_P2P_END = AUTH_ENHANCED_P2P_START + AUTH_ENHANCED_P2P_NUM - 1,
    DIRECT_CHANNEL_SERVER_P2P,
    DIRECT_CHANNEL_CLIENT,
    DIRECT_CHANNEL_SERVER_WIFI,
    DIRECT_CHANNEL_SERVER_HML_START,
    DIRECT_CHANNEL_SERVER_HML_END = DIRECT_CHANNEL_SERVER_HML_START + HML_NUM - 1,
    LANE,
    NETLINK,
    AUTH_RAW_P2P_SERVER,
    AUTH_RAW_P2P_CLIENT,

    LISTENER_MODULE_DYNAMIC_START,
    LISTENER_MODULE_DYNAMIC_END = LISTENER_MODULE_DYNAMIC_START + CONN_DYNAMIC_LISTENER_MODULE_COUNT,
    UNUSE_BUTT,
} ListenerModule;

struct BrInfo {
    char brMac[BT_MAC_LEN];
};
struct BleInfo {
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    BleProtocolType protocol;
    uint32_t psm;
    uint16_t challengeCode;
};
struct ConnSocketInfo {
    char addr[IP_LEN];
    ProtocolType protocol;
    int32_t port;
    int32_t fd;
    int32_t moduleId; /* For details, see {@link ListenerModule}. */
};

typedef struct {
    int32_t isAvailable;
    int32_t isServer;
    ConnectType type;
    union {
        struct BrInfo brInfo;
        struct BleInfo bleInfo;
        struct ConnSocketInfo socketInfo;
    };
} ConnectionInfo;

typedef struct {
    void (*OnConnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnReusedConnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDisconnected)(uint32_t connectionId, const ConnectionInfo *info);
    void (*OnDataReceived)(uint32_t connectionId, ConnModule moduleId, int64_t seq, char *data, int32_t len);
} ConnectCallback;

typedef enum {
    CONN_DEFAULT = 0,
    CONN_LOW,
    CONN_MIDDLE,
    CONN_HIGH
} SendPriority;

typedef enum {
    CONN_SIDE_ANY = 0,
    CONN_SIDE_CLIENT,
    CONN_SIDE_SERVER
} ConnSideType;

typedef struct {
    int32_t module; // ConnModule
    int64_t seq;
    int32_t flag; // SendPriority
    int32_t pid;
    uint32_t len;
    char *buf;
} ConnPostData;

typedef struct {
    void (*OnConnectSuccessed)(uint32_t requestId, uint32_t connectionId, const ConnectionInfo *info);
    void (*OnConnectFailed)(uint32_t requestId, int32_t reason);
} ConnectResult;

struct BrOption {
    char brMac[BT_MAC_LEN];
    uint32_t connectionId;
    ConnSideType sideType;
    uint32_t waitTimeoutDelay;
};

struct BleOption {
    char bleMac[BT_MAC_LEN];
    char deviceIdHash[UDID_HASH_LEN];
    bool fastestConnectEnable;
    uint16_t challengeCode;
    uint32_t psm;
    BleProtocolType protocol;
};

struct BleDirectOption {
    char networkId[NETWORK_ID_BUF_LEN];
    BleProtocolType protoType;
};

struct SocketOption {
    char ifName[NETIF_NAME_LEN];
    char addr[IP_LEN]; /* ipv6 addr format: ip%ifname */
    int32_t port;
    int32_t moduleId; /* For details, see {@link ListenerModule}. */
    ProtocolType protocol;
    int32_t keepAlive;
};

typedef struct {
    ConnectType type;
    union {
        struct BrOption brOption;
        struct BleOption bleOption;
        struct SocketOption socketOption;
        struct BleDirectOption bleDirectOption;
    };
} ConnectOption;

typedef enum {
    CONN_BLE_PRIORITY_BALANCED = 0x0,
    CONN_BLE_PRIORITY_HIGH,
    CONN_BLE_PRIORITY_LOW_POWER,
} ConnectBlePriority;

typedef struct {
    ConnectType type;
    union {
        struct {
            ConnectBlePriority priority;
        } bleOption;
    };
} UpdateOption;

struct ListenerSocketOption {
    char addr[IP_LEN];
    int32_t port;
    ListenerModule moduleId; /* For details, see {@link ListenerModule}. */
    ProtocolType protocol;
    char ifName[NETIF_NAME_LEN];
};

typedef struct {
    ConnectType type;
    union {
        struct ListenerSocketOption socketOption;
    };
} LocalListenerInfo;

typedef struct {
    bool active;
    ConnectType type;
    int32_t windowInMillis;
    int32_t quotaInBytes;
} LimitConfiguration;

/**
 * @ingroup softbus_conn_manager
 * @brief Get connection header size.
 * @return <b>SOFTBUS_OK</b> if the header length get is successfully.
 */
uint32_t ConnGetHeadSize(void);

/**
 * @brief The initialization of the connection server is mainly for the initialization of tcp, br, and ble.
 * This interface is only called once when the soft bus service is created.
 * @see {@link ConnServerDeinit}
 * @return <b>SOFTBUS_OK</b> Successfully initialized connection server
 * returns an error code less than zero otherwise.
 */
int32_t ConnServerInit(void);

/**
 * @brief Deinitialize the connection server, the tcp, br, and ble connection servers will be deinitialized.
 * This interface is only called once when the soft bus service is destroyed.
 * @see {@link ConnServerInit}
 */
void ConnServerDeinit(void);

/**
 * @ingroup Softbus_conn_manager
 * @brief Register connection callback.
 * @see {@link ConnUnSetConnectCallback}
 * @param[in] moduleId Module ID. For details, see {@link ConnModule}.
 * @param[in] callback Indicates a pointer to the connection callback. For details, see {@link ConnectCallback}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null or invalid.
 * @return <b>SOFTBUS_OK</b> if set the connection callback is successfully.
 */
int32_t ConnSetConnectCallback(ConnModule moduleId, const ConnectCallback *callback);

/**
 * @ingroup Softbus_conn_manager
 * @brief Unset the connection callback, clear the callback setting of ConnSetConnectCallback.
 * @see {@link ConnSetConnectCallback}
 * @param[in] moduleId Module ID.For details, see {@link ConnModule}.
 */
void ConnUnSetConnectCallback(ConnModule moduleId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Send data to peer.
 * @param[in] connectionId Connection ID.
 * @param[in] data Connection message content. For details, see {@link ConnPostData}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if any parameter is null.
 * @return <b>SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID</b> if the data parameter length is wrong.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null or invalid.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the bytes result is null.
 * @return <b>SOFTBUS_OK</b> if sending by byte is successfully.
 */
int32_t ConnPostBytes(uint32_t connectionId, ConnPostData *data);

/**
 * @ingroup Softbus_conn_manager
 * @brief Type checking of the connection module to check if this type is supported.
 * @param[in] type Connection type. For details, see {@link ConnectType}.
 * @return <b>SOFTBUS_OK</b> If checked the connection type is successfully.
 */
int32_t ConnTypeIsSupport(ConnectType type);

/**
 * @ingroup Softbus_conn_manager
 * @brief Get inner object based on connection id.
 * @param[in] connectionId Connection ID.
 * @param[in] info Indicates a pointer to the connection information. For details, see {@link ConnectionInfo}.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null or invalid.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the result is null.
 * @return <b>SOFTBUS_OK</b> if the connection information get is successfully.
 */
int32_t ConnGetConnectionInfo(uint32_t connectionId, ConnectionInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief Request connection id.
 * @param[in] moduleId ConnModule module ID. For details, see {@link ConnModule}.
 * @return <b>SOFTBUS_OK</b> if get new request ID is successfully.
 */
uint32_t ConnGetNewRequestId(ConnModule moduleId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Connect the device interface, call this interface to initiate a connection to the remote end.
 * @see {@link ConnDisconnectDevice}
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] requestId Request ID.
 * @param[in] result Indicates a pointer to the connection request. For details, see {@link ConnectResult}.
 * @return <b>SOFTBUS_OK</b> if the connection to the device is successfully
 * returns an error code less than zero otherwise.
 */
int32_t ConnConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

/**
 * @ingroup Softbus_conn_manager
 * @brief Disconnect the device connection interface, disconnect the device logical connection,
 * and disconnect the physical connection when the logical connection reference is zero.
 * @see {@link ConnConnectDevice}
 * @param[in] connectionId Connection ID.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if the disconnection device function of type is null.
 * @return <b>SOFTBUS_OK</b> if the device disconnected is successfully.
 */
int32_t ConnDisconnectDevice(uint32_t connectionId);

/**
 * @ingroup Softbus_conn_manager
 * @brief Disconnects all connected device interfaces,
 * and disconnects the logical and physical connections on the specified device.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the option is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b>
 * if all connected devices all disconnected function of type is null.
 * @return <b>SOFTBUS_OK</b> if all connected devices all disconnected are successfully.
 */
int32_t ConnDisconnectDeviceAllConn(const ConnectOption *option);

/**
 * @ingroup Softbus_conn_manager
 * @brief Stop the local monitoring service and stop monitoring the peer connection event.
 * @see {@link ConnStartLocalListening}
 * @param[in] info Indicates a pointer to local listener information. For details, see {@link LocalListenerInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the info is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if local listener stop function of type is null.
 * @return <b>SOFTBUS_OK</b> if local listener stop successfully.
 */
int32_t ConnStopLocalListening(const LocalListenerInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief Start the local monitoring service and listen for the peer connection event.
 * @see {@link ConnStopLocalListening}
 * @param[in] info Indicates a pointer to local listener information. For details, see {@link LocalListenerInfo}.
 * @return <b>SOFTBUS_INVALID_PARAM</b> if the info is null.
 * @return <b>SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT</b> if the type is null.
 * @return <b>SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT</b> if local listener start function of type is null.
 * @return <b>SOFTBUS_OK</b> if local listeners start successfully.
 */
int32_t ConnStartLocalListening(const LocalListenerInfo *info);

/**
 * @ingroup Softbus_conn_manager
 * @brief call this interface to initiate a ble direct connection to the remote end.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] requestId Request ID.
 * @param[in] result Indicates a pointer to the connection request. For details, see {@link ConnectResult}.
 * @return <b>SOFTBUS_OK</b> if the connection to the device is successfully
 * returns an error code less than zero otherwise.
 */
int32_t ConnBleDirectConnectDevice(const ConnectOption *option, uint32_t requestId, const ConnectResult *result);

/**
 * @ingroup Softbus_conn_manager.
 * @brief call this interface to check ble direct connect support or not.
 * @return <b>false</b> if not support.
 * @return <b>true</b> if support.
 */
bool ConnBleDirectIsEnable(BleProtocolType protocol);

bool CheckActiveConnection(const ConnectOption *option, bool needOccupy);

/**
 * @ingroup Softbus_conn_manager
 * @brief update connection properties as need
 * @param[in] connectionId connection id which should be update.
 * @param[in] option the option will acts on connection
 * @return <b>SOFTBUS_OK</b> if update connection properties successfully, others if failed.
 */
int32_t ConnUpdateConnection(uint32_t connectionId, UpdateOption *option);

/**
 * @ingroup Softbus_conn_manager
 * @brief Prevent connect other devices in specified time.
 * @param[in] option Indicates a pointer to the connection option. For details, see {@link ConnectOption}.
 * @param[in] time time in millisecond
 * @return <b>SOFTBUS_OK</b> if prevent connect other devices successfully, others if failed.
 */
int32_t ConnPreventConnection(const ConnectOption *option, uint32_t time);

/**
 * @ingroup Softbus_conn_manager
 * @brief Obtain link type based on connection ID.
 * @param[in] connectionId Connection ID.
 * @param[out] type Indicates a pointer to the link type. For details, see {@link ConnectType}.
 * @return <b>SOFTBUS_OK</b> if prevent connect other devices successfully, others if failed.
 */
int32_t ConnGetTypeByConnectionId(uint32_t connectionId, ConnectType *type);

/**
 * @ingroup Softbus_conn_manager
 * @param configuration flow control configuration of posting data
 * @return <b>SOFTBUS_OK</b> if success, others if failed.
 */
int32_t ConnConfigPostLimit(const LimitConfiguration *configuration);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */

#endif
