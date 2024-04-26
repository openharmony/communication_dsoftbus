/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#define SOFTBUS_SUB_SYSTEM 203
#define SOFTBUS_ERRNO(module) (-(((SOFTBUS_SUB_SYSTEM) << 21) | ((module) << 16) | (0xFFFF)))
#define SOFTBUS_SUB_ERRNO(module, sub) (-(((SOFTBUS_SUB_SYSTEM) << 21) | ((module) << 16) | ((sub) << 12) | (0x0FFF)))

enum SoftBusSubModule {
    DISC_SUB_MODULE_CODE = 1,
    CONN_SUB_MODULE_CODE = 2,
    AUTH_SUB_MODULE_CODE = 3,
    LNN_SUB_MODULE_CODE = 4,
    TRANS_SUB_MODULE_CODE = 5,
    IPCRPC_SUB_MODULE_CODE = 6,
    PUBLIC_SUB_MODULE_CODE = 10,
    SHORT_DISTANCE_MAPPING_MODULE_CODE = 20,
};

enum DisSubModule {
    DISC_SERVICE_SUB_MODULE_CODE = 1,
    DISC_MANAGER_SUB_MODULE_CODE = 2,
    DISC_BLE_SUB_MODULE_CODE = 3,
    DISC_COAP_SUB_MODULE_CODE = 4,
    DISC_BC_MGR_SUB_MODULE_CODE = 5,
};

enum LnnSubModule {
    LNN_LANE_MODULE_CODE = 1,
};

enum SoftBusErrNo {
    /* errno begin: -((203 << 21) | (10 << 16) | 0xFFFF) */
    SOFTBUS_PUBLIC_ERR_BASE = SOFTBUS_ERRNO(PUBLIC_SUB_MODULE_CODE),
    SOFTBUS_TIMOUT,
    SOFTBUS_INVALID_PARAM,
    SOFTBUS_MEM_ERR,
    SOFTBUS_NOT_IMPLEMENT,
    SOFTBUS_NO_INIT,
    SOFTBUS_CREATE_JSON_ERR,
    SOFTBUS_PARSE_JSON_ERR,
    SOFTBUS_PERMISSION_DENIED,
    SOFTBUS_ACCESS_TOKEN_DENIED,
    SOFTBUS_MALLOC_ERR,
    SOFTBUS_STRCPY_ERR,
    SOFTBUS_ENCRYPT_ERR,
    SOFTBUS_DECRYPT_ERR,
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
    SOFTBUS_DFX_INIT_FAILED,

    SOFTBUS_INVALID_PKGNAME,
    SOFTBUS_FUNC_NOT_SUPPORT,
    SOFTBUS_SERVER_NOT_INIT,
    SOFTBUS_SERVER_NAME_USED,

    SOFTBUS_BLUETOOTH_OFF,
    SOFTBUS_WIFI_OFF,
    SOFTBUS_WIFI_DISCONNECT,
    SOFTBUS_P2P_NOT_SUPPORT,
    SOFTBUS_HML_NOT_SUPPORT,
    SOFTBUS_P2P_ROLE_CONFLICT,
    SOFTBUS_HML_THREE_VAP_CONFLIC,
    SOFTBUS_WIFI_DIRECT_INIT_FAILED,

    /* internal error */
    SOFTBUS_ERR,

    SOFTBUS_NOT_LOGIN, // not login hw account
    SOFTBUS_NOT_SAME_ACCOUNT, // check whether the accounts are the same
    SOFTBUS_NO_ONLINE_DEVICE, // there is no network online device

    /* errno begin: -((203 << 21) | (5 << 16) | 0xFFFF) */
    SOFTBUS_TRANS_ERR_BASE = SOFTBUS_ERRNO(TRANS_SUB_MODULE_CODE),
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
    SOFTBUS_TRANS_CHECK_ACL_FAILED,

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
    SOFTBUS_TRANS_SOCKET_IN_USE,
    SOFTBUS_TRANS_INVALID_SESSION_TYPE,
    SOFTBUS_TRANS_GET_PID_FAILED,
    SOFTBUS_TRANS_INVALID_CHANNEL_ID,
    SOFTBUS_TRANS_PROXY_CREATE_CHANNEL_FAILED,
    SOFTBUS_TRANS_PROXY_SET_CIPHER_FAILED,
    SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_ERR,
    SOFTBUS_TRANS_PROXY_PACK_HANDSHAKE_HEAD_ERR,
    SOFTBUS_TRANS_PROXY_UNPACK_FAST_DATA_FAILED,
    SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_REQUEST_FAILED,
    SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_PKG_FAILED,
    SOFTBUS_TRANS_PROXY_HANDSHAKE_GET_SESSIONKEY_FAILED,
    SOFTBUS_TRANS_UDP_PREPARE_APP_INFO_FAILED,
    SOFTBUS_TRANS_UDP_CHANNEL_ALREADY_EXIST,
    SOFTBUS_TRANS_UDP_PACK_INFO_FAILED,
    SOFTBUS_TRANS_GET_LOCAL_IP_FAILED,
    SOFTBUS_TRANS_TCP_UNUSE_LISTENER_MODE,
    SOFTBUS_TRANS_TCP_GET_AUTHID_FAILED,
    SOFTBUS_TRANS_ADD_TRIGGER_FAILED,
    SOFTBUS_TRANS_ADD_SESSION_CONN_FAILED,
    SOFTBUS_TRANS_GET_SESSION_CONN_FAILED,
    SOFTBUS_TRANS_TCP_GET_SRV_DATA_FAILED,
    SOFTBUS_TRANS_TCP_DATABUF_LESS_ZERO,
    SOFTBUS_TRANS_TCP_GENERATE_SESSIONKEY_FAILED,
    SOFTBUS_TRANS_GET_CIPHER_FAILED,
    SOFTBUS_TRANS_PACK_REQUEST_FAILED,
    SOFTBUS_TRANS_UPDATE_DATA_BUF_FAILED,
    SOFTBUS_TRANS_UNPACK_PACKAGE_HEAD_FAILED,
    SOFTBUS_TRANS_UNPACK_REPLY_FAILED,
    SOFTBUS_TRANS_SET_APP_INFO_FAILED,
    SOFTBUS_TRANS_NOT_META_SESSION,
    SOFTBUS_TRANS_SERVER_INIT_FAILED,
    SOFTBUS_TRANS_SESSION_SERVER_NOT_FOUND,
    SOFTBUS_TRANS_ENCRYPT_ERR,
    SOFTBUS_TRANS_DECRYPT_ERR,
    SOFTBUS_TRANS_BAD_KEY, // Send badkey notification for offline events
    SOFTBUS_TRANS_CHECK_PID_ERROR,
    SOFTBUS_TRANS_GET_LOCAL_UID_FAIL, // get local userId fail
    SOFTBUS_TRANS_MSG_BUILD_BC_PARAM_FAIL, // build broadcast params fail
    SOFTBUS_TRANS_MSG_BUILD_PAYLOAD_FAIL, // build broadcast payload fail
    SOFTBUS_TRANS_MSG_INIT_FAIL, // notification message init fail
    SOFTBUS_TRANS_MSG_REPLACE_PAYLOAD_FAIL, // replace payload without stopping the broadcast fail
    SOFTBUS_TRANS_UDP_CHANNEL_NOT_FOUND,
    SOFTBUS_TRANS_TDC_CHANNEL_ALREADY_EXIST, // receive repeat tdc channel open request
    SOFTBUS_TRANS_UDP_SET_CHANNEL_FAILED,
    SOFTBUS_TRANS_STOP_BIND_BY_CANCEL,
    SOFTBUS_TRANS_PROXY_GET_AUTH_ID_FAILED,

    /* errno begin: -((203 << 21) | (3 << 16) | 0xFFFF) */
    SOFTBUS_AUTH_ERR_BASE = SOFTBUS_ERRNO(AUTH_SUB_MODULE_CODE),
    SOFTBUS_AUTH_INIT_FAIL,
    SOFTBUS_AUTH_CONN_FAIL,
    SOFTBUS_AUTH_CONN_INIT_FAIL,
    SOFTBUS_AUTH_CONN_TIMEOUT,
    SOFTBUS_AUTH_GET_BR_CONN_INFO_FAIL,
    SOFTBUS_AUTH_GET_SESSION_INFO_FAIL,
    SOFTBUS_AUTH_GET_SESSION_KEY_FAIL,
    SOFTBUS_AUTH_GET_FSM_FAIL,
    SOFTBUS_AUTH_REG_DATA_FAIL,
    SOFTBUS_AUTH_DEVICE_DISCONNECTED,
    SOFTBUS_AUTH_SYNC_DEVID_FAIL,
    SOFTBUS_AUTH_HICHAIN_AUTH_FAIL,
    SOFTBUS_AUTH_HICHAIN_PROCESS_FAIL,
    SOFTBUS_AUTH_HICHAIN_AUTH_ERROR,
    SOFTBUS_AUTH_HICHAIN_NOT_TRUSTED,
    SOFTBUS_AUTH_SYNC_DEVINFO_FAIL,
    SOFTBUS_AUTH_UNPACK_DEVINFO_FAIL,
    SOFTBUS_AUTH_SEND_FAIL,
    SOFTBUS_AUTH_TIMEOUT,
    SOFTBUS_AUTH_NOT_FOUND,
    SOFTBUS_AUTH_INNER_ERR,
    SOFTBUS_AUTH_CONN_START_ERR,
    SOFTBUS_AUTH_START_ERR,
    SOFTBUS_AUTH_EXCHANGE_DEVICE_INFO_START_ERR,

    /* errno begin: -((203 << 21) | (4 << 16) | 0xFFFF) */
    SOFTBUS_NETWORK_ERR_BASE = SOFTBUS_ERRNO(LNN_SUB_MODULE_CODE),
    SOFTBUS_NETWORK_CONN_FSM_DEAD,
    SOFTBUS_NETWORK_JOIN_CANCELED,
    SOFTBUS_NETWORK_JOIN_LEAVING,
    SOFTBUS_NETWORK_JOIN_TIMEOUT,
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
    SOFTBUS_NETWORK_NOT_CONNECTABLE,
    SOFTBUS_NETWORK_NODE_DIRECT_ONLINE,
    SOFTBUS_NETWORK_NOT_INIT,
    SOFTBUS_NETWORK_LOOPER_ERR,
    SOFTBUS_NETWORK_GET_NODE_INFO_ERR,
    SOFTBUS_NETWORK_GET_ALL_NODE_INFO_ERR,
    SOFTBUS_NETWORK_GET_LOCAL_NODE_INFO_ERR,
    SOFTBUS_NETWORK_GET_DEVICE_INFO_ERR,
    SOFTBUS_NETWORK_DELETE_INFO_ERR,
    SOFTBUS_NETWORK_REG_EVENT_HANDLER_ERR,
    SOFTBUS_NETWORK_JOIN_REQUEST_ERR,
    SOFTBUS_NETWORK_NOT_FOUND,
    SOFTBUS_NETWORK_NODE_KEY_INFO_ERR,
    SOFTBUS_NETWORK_ACTIVE_META_NODE_ERR,
    SOFTBUS_NETWORK_DEACTIVE_META_NODE_ERR,
    SOFTBUS_NETWORK_GET_META_NODE_INFO_ERR,
    SOFTBUS_NETWORK_JOIN_LNN_START_ERR,
    SOFTBUS_NETWORK_LEAVE_LNN_START_ERR,
    SOFTBUS_CENTER_SERVER_INIT_FAILED,

    /* errno begin: -((203 << 21) | (4 << 16) | (1 << 12) | 0x0FFF) */
    SOFTBUS_LANE_ERR_BASE = SOFTBUS_SUB_ERRNO(LNN_SUB_MODULE_CODE, LNN_LANE_MODULE_CODE),
    SOFTBUS_LANE_SELECT_FAIL,
    SOFTBUS_LANE_TRIGGER_LINK_FAIL,
    SOFTBUS_LANE_GET_LEDGER_INFO_ERR,
    SOFTBUS_LANE_DETECT_FAIL,
    SOFTBUS_LANE_ID_GENERATE_FAIL,
    SOFTBUS_LANE_GUIDE_BUILD_FAIL,

    /* errno begin: -((203 << 21) | (2 << 16) | 0xFFFF) */
    SOFTBUS_CONN_ERR_BASE = SOFTBUS_ERRNO(CONN_SUB_MODULE_CODE),
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
    SOFTBUS_CONN_SERVER_INIT_FAILED,

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
    SOFTBUS_CONN_BR_UNDERLAY_PAGE_TIMEOUT_ERR,

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
    SOFTBUS_CONN_BLE_RECV_MSG_ERROR,

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

    SOFTBUS_CONN_LINK_BROADCAST_START_ADV_FAIL,
    SOFTBUS_CONN_LINK_BROADCAST_QUERY_RPA_FAIL,

    SOFTBUS_BLECONNECTION_REG_GATTS_CALLBACK_FAIL,
    SOFTBUS_GATTC_INTERFACE_FAILED,

    SOFTBUS_TCPCONNECTION_SOCKET_ERR,
    SOFTBUS_TCPFD_NOT_IN_TRIGGER,
    SOFTBUS_CONN_BLE_DIRECT_INIT_FAILED,
    SOFTBUS_SOCKET_ADDR_ERR,
    SOFTBUS_SOCKET_BIND_ERR,

    /* soft bus connection mapping short range conflict error code */
    SOFTBUS_CONN_SHORT_RANGE_BASE = SOFTBUS_ERRNO(CONN_SUB_MODULE_CODE) + 1000,
    SOFTBUS_CONN_ACTIVE_TYPE_NO_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_NO_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_ERROR,
    SOFTBUS_CONN_PASSIVE_TYPE_ERROR,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_STA_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_P2P_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_STA_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_STA_P2P_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_STA_P2P_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_AP_P2P_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_AP_P2P_HML_CHIP_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_55_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_55_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_225_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_225_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_255_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_255_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_525_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_525_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_STA_P2P_HML_555_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_STA_P2P_HML_555_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_P2P_GO_GC_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_P2P_GO_GC_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_P2P_NUM_LIMITED_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_P2P_NUM_LIMITED_CONFLICT,
    SOFTBUS_CONN_ACTIVE_TYPE_HML_NUM_LIMITED_CONFLICT,
    SOFTBUS_CONN_PASSIVE_TYPE_HML_NUM_LIMITED_CONFLICT,

    /* errno begin: -((203 << 21) | (1 << 16) | 0xFFFF) */
    SOFTBUS_DISCOVER_ERR_BASE = SOFTBUS_ERRNO(DISC_SUB_MODULE_CODE),
    /* errno begin: -((203 << 21) | (1 << 16) | (1 << 12) | 0x0FFF) */
    SOFTBUS_DISCOVER_SERVICE_ERR_BASE = SOFTBUS_SUB_ERRNO(DISC_SUB_MODULE_CODE, DISC_SERVICE_SUB_MODULE_CODE),
    SOFTBUS_DISCOVER_NOT_INIT,
    SOFTBUS_DISC_SERVER_INIT_FAILED,
    /* errno begin: -((203 << 21) | (1 << 16) | (2 << 12) | 0x0FFF) */
    SOFTBUS_DISCOVER_MANAGER_ERR_BASE = SOFTBUS_SUB_ERRNO(DISC_SUB_MODULE_CODE, DISC_MANAGER_SUB_MODULE_CODE),
    SOFTBUS_DISCOVER_MANAGER_NOT_INIT,
    SOFTBUS_DISCOVER_MANAGER_INIT_FAIL,
    SOFTBUS_DISCOVER_MANAGER_ITEM_NOT_CREATE,
    SOFTBUS_DISCOVER_MANAGER_INFO_NOT_CREATE,
    SOFTBUS_DISCOVER_MANAGER_INFO_NOT_DELETE,
    SOFTBUS_DISCOVER_MANAGER_INNERFUNCTION_FAIL,
    SOFTBUS_DISCOVER_MANAGER_CAPABILITY_INVALID,
    SOFTBUS_DISCOVER_MANAGER_DUPLICATE_PARAM,
    SOFTBUS_DISCOVER_MANAGER_INVALID_MEDIUM,
    /* errno begin: -((203 << 21) | (1 << 16) | (3 << 12) | 0x0FFF) */
    SOFTBUS_DISCOVER_BLE_ERR_BASE = SOFTBUS_SUB_ERRNO(DISC_SUB_MODULE_CODE, DISC_BLE_SUB_MODULE_CODE),
    SOFTBUS_DISCOVER_BLE_DISPATCHER_FAIL,
    SOFTBUS_DISCOVER_BLE_GET_BROADCAST_DATA_FAIL,
    SOFTBUS_DISCOVER_BLE_BUILD_CONFIG_ADV_DATA_FAIL,
    SOFTBUS_DISCOVER_BLE_REGISTER_CAP_FAIL,
    SOFTBUS_DISCOVER_BLE_START_BROADCAST_FAIL,
    SOFTBUS_DISCOVER_BLE_END_BROADCAST_FAIL,
    SOFTBUS_DISCOVER_BLE_START_SCAN_FAIL,
    SOFTBUS_DISCOVER_BLE_END_SCAN_FAIL,
    /* errno begin: -((203 << 21) | (1 << 16) | (4 << 12) | 0x0FFF) */
    SOFTBUS_DISCOVER_COAP_ERR_BASE = SOFTBUS_SUB_ERRNO(DISC_SUB_MODULE_CODE, DISC_COAP_SUB_MODULE_CODE),
    SOFTBUS_DISCOVER_COAP_NOT_INIT,
    SOFTBUS_DISCOVER_COAP_INIT_FAIL,
    SOFTBUS_DISCOVER_COAP_MERGE_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_CANCEL_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_REGISTER_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_SET_FILTER_CAP_FAIL,
    SOFTBUS_DISCOVER_COAP_START_PUBLISH_FAIL,
    SOFTBUS_DISCOVER_COAP_STOP_PUBLISH_FAIL,
    SOFTBUS_DISCOVER_COAP_START_DISCOVER_FAIL,
    SOFTBUS_DISCOVER_COAP_STOP_DISCOVER_FAIL,
    /* errno begin: -((203 << 21) | (1 << 16) | (5 << 12) | 0x0FFF) */
    SOFTBUS_DISCOVER_BC_MGR_ERR_BASE = SOFTBUS_SUB_ERRNO(DISC_SUB_MODULE_CODE, DISC_BC_MGR_SUB_MODULE_CODE),
    SOFTBUS_BC_MGR_NO_FUNC_REGISTERED, // no medium has registered
    SOFTBUS_BC_MGR_FUNC_NULL, // the function registered is null
    SOFTBUS_BC_MGR_BUILD_ADV_PACKT_FAIL, // build broadcast adv packet fail
    SOFTBUS_BC_MGR_BUILD_RSP_PACKT_FAIL, // build broadcast rsp packet fail
    SOFTBUS_BC_MGR_INVALID_BC_ID, // invalid broadcast id
    SOFTBUS_BC_MGR_INVALID_LISN_ID, // invalid listener id
    SOFTBUS_BC_MGR_INVALID_SRV, // invalid service type
    SOFTBUS_BC_MGR_NOT_BROADCASTING, // not broadcasting
    SOFTBUS_BC_MGR_START_SCAN_NO_FILTER, // start scan without setting filter
    SOFTBUS_BC_MGR_REG_NO_AVAILABLE_BC_ID, // no available broadcast id
    SOFTBUS_BC_MGR_REG_NO_AVAILABLE_LISN_ID, // no available listener id
    SOFTBUS_BC_MGR_REG_DUP, // duplicate registration
    SOFTBUS_BC_MGR_WAIT_COND_FAIL, // wait signal fail

    /* softbus ok */
    SOFTBUS_OK = 0,
};

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_ERRCODE_H */
