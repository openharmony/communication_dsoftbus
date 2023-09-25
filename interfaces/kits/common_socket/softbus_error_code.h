/*
 * Copyright (c) 2023 Huawei Device Co., Ltd.
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

/**
 * @addtogroup SoftBus
 * @{
 *
 * @brief Provides high-speed, secure communication between devices.
 *
 * This module implements unified distributed communication capability management between nearby devices, and provides
 * link-independent device discovery and transmission interfaces to support service publishing and data transmission.
 *
 * @since 1.0
 * @version 1.0
 */
/** @} */

/**
 * @file softbus_error_code.h
 *
 * @brief Declares error code
 *
 * @since 1.0
 * @version 1.0
 */

#ifndef SOFTBUS_ERROR_CODE_H
#define SOFTBUS_ERROR_CODE_H

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

enum SoftBusModuleBase {
    DISCOVER_BASE_ERROR = 100000,
    CONNECT_BASE_ERROR = 200000,
    NETWORK_BASE_ERROR = 300000,
    TRANSPORT_BASE_ERROR = 400000,
    CONNECT_LINK_TYPE_BR = ((1 << 24) & 0xFF000000),
};

enum SoftBusSubModule {
    SOFTBUS_MODULE_CODE = 203 << 21,
    COMMON_SUB_MODULE_CODE = 1 << 16,
    DISCOVER_SUB_MODULE_CODE = 10 << 16,
    CONNECT_SUB_MODULE_CODE = 11 << 16,
    NETWORK_SUB_MODULE_CODE = 12 << 16,
    TRANSPORT_SUB_MODULE_CODE = 13 << 16,
    BR_LINK_SUB_MODULE_CODE = 14 << 10,
    FAIL_RET_EX = 2,
};

enum SoftBusModule {
    SOFTBUS_MOD_COMMON = 0,
    SOFTBUS_MOD_PLUGIN,
    SOFTBUS_MOD_TRANS,
    SOFTBUS_MOD_AUTH,
    SOFTBUS_MOD_LNN,
    SOFTBUS_MOD_CONNECT,
    SOFTBUS_MOD_DISCOVERY,
    SOFTBUS_MOD_PUBLIC,
};
#define SOFTBUS_ERRNO(module) ((0xF << 28) | ((1 << (module)) << 16))

enum SoftBusErrNo {
    /* errno begin: 0xF0010000 */
    SOFTBUS_COMMOM_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_COMMON),
    SOFTBUS_TIMOUT,
    SOFTBUS_INVALID_PARAM,
    SOFTBUS_MEM_ERR,
    SOFTBUS_NOT_IMPLEMENT,
    SOFTBUS_NO_URI_QUERY_KEY,
    SOFTBUS_NO_INIT,
    SOFTBUS_CREATE_JSON_ERR,
    SOFTBUS_PARSE_JSON_ERR,
    SOFTBUS_PERMISSION_DENIED,
    SOFTBUS_ACCESS_TOKEN_DENIED,
    SOFTBUS_MALLOC_ERR,
    SOFTBUS_STRCPY_ERR,
    SOFTBUS_ENCRYPT_ERR,
    SOFTBUS_DECRYPT_ERR,
    SOFTBUS_INVALID_SESS_OPCODE,
    SOFTBUS_INVALID_NUM,
    SOFTBUS_SERVER_NAME_REPEATED,
    SOFTBUS_TCP_SOCKET_ERR,
    SOFTBUS_LOCK_ERR,
    SOFTBUS_GET_REMOTE_UUID_ERR,
    SOFTBUS_NO_ENOUGH_DATA,
    SOFTBUS_INVALID_DATA_HEAD,
    SOFTBUS_INVALID_FD,
    SOFTBUS_FILE_ERR,
    SOFTBUS_DATA_NOT_ENOUGH,
    SOFTBUS_SLICE_ERROR,
    SOFTBUS_ALREADY_EXISTED,
    SOFTBUS_GET_CONFIG_VAL_ERR,
    SOFTBUS_PEER_PROC_ERR,
    SOFTBUS_NOT_FIND,
    SOFTBUS_ALREADY_TRIGGERED,
    SOFTBUS_FILE_BUSY,
    SOFTBUS_IPC_ERR,

    SOFTBUS_INVALID_PKGNAME,
    SOFTBUS_FUNC_NOT_SUPPORT,
    SOFTBUS_SERVER_NOT_INIT,
    SOFTBUS_SERVER_NAME_USED,

    /* errno begin: 0xF0020000 */
    SOFTBUS_PLUGIN_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_PLUGIN),

    /* errno begin: 0xF0040000 */
    SOFTBUS_TRANS_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_TRANS),
    SOFTBUS_TRANS_INVALID_SESSION_ID,
    SOFTBUS_TRANS_INVALID_SESSION_NAME,
    SOFTBUS_TRANS_INVALID_CHANNEL_TYPE,
    SOFTBUS_TRANS_INVALID_CLOSE_CHANNEL_ID,
    SOFTBUS_TRANS_BUSINESS_TYPE_NOT_MATCH,
    SOFTBUS_TRANS_SESSION_REPEATED,
    SOFTBUS_TRANS_SESSION_CNT_EXCEEDS_LIMIT,
    SOFTBUS_TRANS_SESSIONSERVER_NOT_CREATED,
    SOFTBUS_TRANS_SESSION_OPENING,
    SOFTBUS_TRANS_GET_LANE_INFO_ERR,
    SOFTBUS_TRANS_CREATE_CHANNEL_ERR,
    SOFTBUS_TRANS_INVALID_DATA_LENGTH,
    SOFTBUS_TRANS_FUNC_NOT_SUPPORT,
    SOFTBUS_TRANS_OPEN_AUTH_CHANNANEL_FAILED,
    SOFTBUS_TRANS_GET_P2P_INFO_FAILED,
    SOFTBUS_TRANS_OPEN_AUTH_CONN_FAILED,

    SOFTBUS_TRANS_PROXY_PACKMSG_ERR,
    SOFTBUS_TRANS_PROXY_SENDMSG_ERR,
    SOFTBUS_TRANS_PROXY_SEND_CHANNELID_INVALID,
    SOFTBUS_TRANS_PROXY_CHANNLE_STATUS_INVALID,
    SOFTBUS_TRANS_PROXY_DEL_CHANNELID_INVALID,
    SOFTBUS_TRANS_PROXY_SESS_ENCRYPT_ERR,
    SOFTBUS_TRANS_PROXY_INVALID_SLICE_HEAD,
    SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_NO_INVALID,
    SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_EXCEED_LENGTH,
    SOFTBUS_TRANS_PROXY_ASSEMBLE_PACK_DATA_NULL,

    SOFTBUS_TRANS_UDP_CLOSE_CHANNELID_INVALID,
    SOFTBUS_TRANS_UDP_SERVER_ADD_CHANNEL_FAILED,
    SOFTBUS_TRANS_UDP_CLIENT_ADD_CHANNEL_FAILED,
    SOFTBUS_TRANS_UDP_SERVER_NOTIFY_APP_OPEN_FAILED,
    SOFTBUS_TRANS_UDP_CLIENT_NOTIFY_APP_OPEN_FAILED,
    SOFTBUS_TRANS_UDP_START_STREAM_SERVER_FAILED,
    SOFTBUS_TRANS_UDP_START_STREAM_CLIENT_FAILED,
    SOFTBUS_TRANS_UDP_SEND_STREAM_FAILED,
    SOFTBUS_TRANS_UDP_GET_CHANNEL_FAILED,
    SOFTBUS_TRANS_UDP_CHANNEL_DISABLE,

    SOFTBUS_TRANS_QOS_REPORT_FAILED,
    SOFTBUS_TRANS_QOS_REPORT_TOO_FREQUENT,

    SOFTBUS_TRANS_SESSION_SERVER_NOINIT,
    SOFTBUS_TRANS_SESSION_INFO_NOT_FOUND,
    SOFTBUS_TRANS_SESSION_CREATE_FAILED,
    SOFTBUS_TRANS_SESSION_ADDPKG_FAILED,
    SOFTBUS_TRANS_SESSION_SET_CHANNEL_FAILED,
    SOFTBUS_TRANS_SESSION_NO_ENABLE,
    SOFTBUS_TRANS_SESSION_GROUP_INVALID,
    SOFTBUS_TRANS_SESSION_NAME_NO_EXIST,
    SOFTBUS_TRANS_SESSION_GET_CHANNEL_FAILED,

    SOFTBUS_TRANS_PROXY_REMOTE_NULL,
    SOFTBUS_TRANS_PROXY_WRITETOKEN_FAILED,
    SOFTBUS_TRANS_PROXY_WRITECSTRING_FAILED,
    SOFTBUS_TRANS_PROXY_WRITERAWDATA_FAILED,
    SOFTBUS_TRANS_PROXY_READRAWDATA_FAILED,
    SOFTBUS_TRANS_PROXY_SEND_REQUEST_FAILED,
    SOFTBUS_TRANS_PROXY_INVOKE_FAILED,
    SOFTBUS_TRANS_PROXY_CHANNEL_NOT_FOUND,

    SOFTBUS_TRANS_SEND_LEN_BEYOND_LIMIT,
    SOFTBUS_TRANS_FILE_LISTENER_NOT_INIT,
    SOFTBUS_TRANS_STREAM_ONLY_UDP_CHANNEL,
    SOFTBUS_TRANS_CHANNEL_TYPE_INVALID,
    SOFTBUS_TRANS_TDC_CHANNEL_NOT_FOUND,
    SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_PENDING,
    SOFTBUS_TRANS_TDC_PENDINGLIST_NOT_FOUND,
    SOFTBUS_TRANS_AUTH_CHANNEL_NOT_FOUND,
    SOFTBUS_TRANS_NET_STATE_CHANGED,
    SOFTBUS_TRANS_HANDSHAKE_TIMEOUT,
    SOFTBUS_TRANS_HANDSHAKE_ERROR,
    SOFTBUS_TRANS_PEER_SESSION_NOT_CREATED,
    SOFTBUS_TRANS_PROXY_DISCONNECTED,
    SOFTBUS_TRANS_AUTH_NOTALLOW_OPENED,
    SOFTBUS_TRANS_PROXY_ERROR_APP_TYPE,
    SOFTBUS_TRANS_PROXY_CONN_REPEAT,
    SOFTBUS_TRANS_PROXY_CONN_ADD_REF_FAILED,

    /* errno begin: 0xF0080000 */
    SOFTBUS_AUTH_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_AUTH),
    SOFTBUS_AUTH_INIT_FAIL,
    SOFTBUS_AUTH_CONN_FAIL,
    SOFTBUS_AUTH_CONN_TIMEOUT,
    SOFTBUS_AUTH_DEVICE_DISCONNECTED,
    SOFTBUS_AUTH_SYNC_DEVID_FAIL,
    SOFTBUS_AUTH_UNPACK_DEVID_FAIL,
    SOFTBUS_AUTH_HICHAIN_AUTH_FAIL,
    SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL,
    SOFTBUS_AUTH_HICHAIN_TRANSMIT_FAIL,
    SOFTBUS_AUTH_HICHAIN_AUTH_ERROR,
    SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED,
    SOFTBUS_AUTH_SYNC_DEVINFO_FAIL,
    SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL,
    SOFTBUS_AUTH_SEND_FAIL,
    SOFTBUS_AUTH_TIMEOUT,
    SOFTBUS_AUTH_NOT_FOUND,
    SOFTBUS_AUTH_INNER_ERR,

    /* errno begin: 0xF0100000 */
    SOFTBUS_NETWORK_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_LNN),
    SOFTBUS_NETWORK_CONN_FSM_DEAD,
    SOFTBUS_NETWORK_JOIN_CANCELED,
    SOFTBUS_NETWORK_JOIN_LEAVING,
    SOFTBUS_NETWORK_JOIN_TIMEOUT,
    SOFTBUS_NETWORK_UNPACK_DEV_INFO_FAILED,
    SOFTBUS_NETWORK_DEV_NOT_TRUST,
    SOFTBUS_NETWORK_LEAVE_OFFLINE,
    SOFTBUS_NETWORK_AUTH_DISCONNECT,
    SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_ERR,     // time sync channel pipe broken
    SOFTBUS_NETWORK_TIME_SYNC_HANDSHAKE_TIMEOUT, // timeout during handshake
    SOFTBUS_NETWORK_TIME_SYNC_TIMEOUT,           // timeout during sync
    SOFTBUS_NETWORK_TIME_SYNC_INTERFERENCE,      // interference
    SOFTBUS_NETWORK_HEARTBEAT_REPEATED,
    SOFTBUS_NETWORK_HEARTBEAT_UNTRUSTED,
    SOFTBUS_NETWORK_HEARTBEAT_EMPTY_LIST,
    SOFTBUS_NETWORK_NODE_OFFLINE,
    SOFTBUS_NETWORK_NODE_DIRECT_ONLINE,
    SOFTBUS_NETWORK_NOT_INIT,
    SOFTBUS_NETWORK_LOOPER_ERR,
    SOFTBUS_NETWORK_AUTH_TCP_ERR,
    SOFTBUS_NETWORK_AUTH_BLE_ERR,
    SOFTBUS_NETWORK_AUTH_BR_ERR,
    SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR,
    SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR,
    SOFTBUS_NETWORK_NODE_KEY_INFO_ERR,
    SOFTBUS_NETWORK_ACTIVE_META_NODE_ERR,
    SOFTBUS_NETWORK_DEACTIVE_META_NODE_ERR,
    SOFTBUS_NETWORK_GET_META_NODE_INFO_ERR,

    /* errno begin: 0xF0200000 */
    SOFTBUS_CONN_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_CONNECT),
    SOFTBUS_CONN_FAIL,
    SOFTBUS_CONN_MANAGER_TYPE_NOT_SUPPORT,
    SOFTBUS_CONN_MANAGER_OP_NOT_SUPPORT,
    SOFTBUS_CONN_MANAGER_PKT_LEN_INVALID,
    SOFTBUS_CONN_MANAGER_LIST_NOT_INIT,
    SOFTBUS_CONN_INVALID_CONN_TYPE,
    SOFTBUS_CONNECTION_BASE,
    SOFTBUS_CONNECTION_ERR_CLOSED,
    SOFTBUS_CONNECTION_ERR_DRIVER_CONGEST,
    SOFTBUS_CONNECTION_ERR_SOFTBUS_CONGEST,
    SOFTBUS_CONNECTION_ERR_CONNID_INVALID,
    SOFTBUS_CONNECTION_ERR_SENDQUEUE_FULL,

    /* common error for bluetooth medium */
    SOFTBUS_CONN_BLUETOOTH_OFF,

    SOFTBUS_CONN_BR_INTERNAL_ERR,
    SOFTBUS_CONN_BR_INVALID_ADDRESS_ERR,
    SOFTBUS_CONN_BR_CONNECT_TIMEOUT_ERR,
    SOFTBUS_CONN_BR_CONNECTION_NOT_EXIST_ERR,
    SOFTBUS_CONN_BR_CONNECTION_NOT_READY_ERR,
    SOFTBUS_CONN_BR_CONNECTION_INVALID_SOCKET,
    SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL,
    SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL,
    SOFTBUS_CONN_BR_UNDERLAY_SOCKET_CLOSED,
    SOFTBUS_CONN_BR_UNDERLAY_READ_FAIL,

    SOFTBUS_CONN_BLE_INTERNAL_ERR,
    SOFTBUS_CONN_BLE_CONNECT_PREVENTED_ERR,
    SOFTBUS_CONN_BLE_DISCONNECT_DIRECTLY_ERR,
    SOFTBUS_CONN_BLE_DISCONNECT_WAIT_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_CONNECT_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_EXCHANGE_BASIC_INFO_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_CONNECTION_NOT_EXIST_ERR,
    SOFTBUS_CONN_BLE_CONNECTION_NOT_READY_ERR,
    SOFTBUS_CONN_BLE_CLIENT_STATE_UNEXPECTED_ERR,
    SOFTBUS_CONN_BLE_SERVER_STATE_UNEXPECTED_ERR,
    SOFTBUS_CONN_BLE_SERVER_START_SERVER_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_SERVER_STOP_SERVER_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_DISCONNECT_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONNECT_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_DISCONNECT_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_DISCONNECT_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_SEARCH_SERVICE_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_GET_SERVICE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_REGISTER_NOTIFICATION_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_CONFIGURE_MTU_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CLIENT_WRITE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVER_REGISTER_CALLBACK_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVER_ADD_SERVICE_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_ADD_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_ADD_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_START_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_STOP_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_DELETE_FAIL,
    SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_SERVICE_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_CHARACTERISTIC_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_UNKNOWN_DESCRIPTOR_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_SERVICE_HANDLE_MISMATCH_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_CHARACTERISTIC_HANDLE_MISMATCH_ERR,
    SOFTBUS_CONN_BLE_UNDERLAY_DESCRIPTOR_HANDLE_MISMATCH_ERR,

    SOFTBUS_CONN_BLE_COC_INTERNAL_ERR,
    SOFTBUS_CONN_BLE_COC_INVALID_ADDRESS_ERR,
    SOFTBUS_CONN_BLE_COC_CONNECT_TIMEOUT_ERR,
    SOFTBUS_CONN_BLE_COC_CONNECTION_NOT_EXIST_ERR,
    SOFTBUS_CONN_BLE_COC_CONNECTION_NOT_READY_ERR,
    SOFTBUS_CONN_BLE_COC_CONNECTION_INVALID_SOCKET,
    SOFTBUS_CONN_BLE_COC_UNDERLAY_CONNECT_FAIL,
    SOFTBUS_CONN_BLE_COC_UNDERLAY_WRITE_FAIL,
    SOFTBUS_CONN_BLE_COC_UNDERLAY_SOCKET_CLOSED,
    SOFTBUS_CONN_BLE_COC_UNDERLAY_READ_FAIL,

    SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL,
    SOFTBUS_GATTC_INTERFACE_FAILED,

    SOFTBUS_TCPCONNECTION_SOCKET_ERR,
    SOFTBUS_TCPFD_NOT_IN_TRIGGER,

    /* errno begin: 0xF0400000 */
    SOFTBUS_DISCOVER_ERR_BASE = SOFTBUS_ERRNO(SOFTBUS_MOD_DISCOVERY),
    SOFTBUS_DISCOVER_NOT_INIT,
    SOFTBUS_DISCOVER_INVALID_PKGNAME,
    SOFTBUS_DISCOVER_SERVER_NO_PERMISSION,
    SOFTBUS_DISCOVER_MANAGER_NOT_INIT,
    SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE,
    SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE,
    SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE,
    SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL,
    SOFTBUS_DISCOVER_MANAGER_CAPABILITY_INVALID,
    SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM,
    SOFTBUS_DISCOVER_MANAGER_INVALID_PARAM,
    SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM,
    SOFTBUS_DISCOVER_MANAGER_INVALID_PKGNAME,
    SOFTBUS_DISCOVER_MANAGER_INVALID_MODULE,
    SOFTBUS_DISCOVER_COAP_NOT_INIT,
    SOFTBUS_DISCOVER_COAP_INIT_FAIL,
    SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_REGISTER_DEVICE_FAIL,
    SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL,
    SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL,
    SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL,
    SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL,

    /* errno begin: 0xF0800000 */
    SOFTBUS_PUBLIC_ERR_BASE = (-13000),

    /* internal error */
    SOFTBUS_ERR = (-1),
    /* softbus ok */
    SOFTBUS_OK = 0,
};

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ERRCODE_H */
