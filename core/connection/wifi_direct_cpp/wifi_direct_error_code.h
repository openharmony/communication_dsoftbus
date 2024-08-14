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

#ifndef WIFI_DIRECT_ERROR_CODE_H
#define WIFI_DIRECT_ERROR_CODE_H

#ifdef __cplusplus
#include <cstdlib>
#else
#include <stdlib.h>
#endif
#include "softbus_error_code.h"

#ifdef __cplusplus
extern "C" {
#endif

enum WifiDirectErrorCode {
    /* Error code representing OK */
    OK = 0,

    /* Error code representing start position of V1 errors. */
    V1_ERROR_START = -401000,

    /* Indicating cannot build a p2p link because the device is already connected with a mismatch role. */
    V1_ERROR_CONNECTED_WITH_MISMATCHED_ROLE = V1_ERROR_START - 1,

    /* Indicating cannot build a p2p link because this device is already be GC. */
    V1_ERROR_GC_CONNECTED_TO_ANOTHER_DEVICE = V1_ERROR_START - 2,

    /* Indicating cannot build a p2p link because this device cannot be connected with the specified role. */
    V1_ERROR_AVAILABLE_WITH_MISMATCHED_ROLE = V1_ERROR_START - 3,

    /* Indicating cannot build a p2p link because the remote device is already be GC. */
    V1_ERROR_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE = V1_ERROR_START - 4,

    /* Indicating cannot build a p2p link because both the devices are GO. */
    V1_ERROR_BOTH_GO = V1_ERROR_START - 5,

    /* Indicating that two devices initiate a connection to peer device at the same time. */
    V1_ERROR_TWO_WAY_SIMULTANEOUS_CONNECTION = V1_ERROR_START - 6,

    /* Indicating that this connect request has timed out. */
    V1_ERROR_CONNECT_TIMEOUT = V1_ERROR_START - 7,

    /* Indicating that failure occurred when reusing p2p link. */
    V1_ERROR_REUSE_FAILED = V1_ERROR_START - 8,

    /* Indicating that p2p link is used by another service. */
    V1_ERROR_LINK_USED_BY_ANOTHER_SERVICE = V1_ERROR_START - 9,

    /* Indicating that GOInfo is wrong. */
    V1_ERROR_WRONG_GO_INFO = V1_ERROR_START - 10,

    /* Indicating that GCInfo is wrong. */
    V1_ERROR_WRONG_GC_INFO = V1_ERROR_START - 11,

    /* Indicating that post message to remote device via AuthConnection has failed. */
    V1_ERROR_POST_MESSAGE_FAILED = V1_ERROR_START - 12,

    /* Indicating that cannot build a p2p link because current device is busy. */
    V1_ERROR_BUSY = V1_ERROR_START - 15,

    /* Indicating that peer device is not a trusted device. */
    V1_ERROR_NOT_TRUSTED_DEVICE = V1_ERROR_START - 17,

    /* Indicating that connect group failed. */
    V1_ERROR_CONNECT_GROUP_FAILED = V1_ERROR_START - 18,

    /* Indicating that create group failed. */
    V1_ERROR_CREATE_GROUP_FAILED = V1_ERROR_START - 19,

    /* Indicating that connect group timeout. */
    V1_ERROR_PEER_CONNECT_GROUP_FAILED = V1_ERROR_START - 20,

    /* Indicating that create group timeout. */
    V1_ERROR_PEER_CREATE_GROUP_FAILED = V1_ERROR_START - 21,

    /* Indicating that create group timeout. */
    V1_ERROR_RPT_ENABLED = V1_ERROR_START - 22,

    /* Indicating that create group timeout. */
    V1_ERROR_PEER_RPT_ENABLED = V1_ERROR_START - 23,

    /* Indicating unknown reason. */
    V1_ERROR_UNKNOWN = V1_ERROR_START - 24,

    /* Indicating p2p interface is not available */
    V1_ERROR_IF_NOT_AVAILABLE = V1_ERROR_START - 25,

    /* Error code representing end position of v1 errors. */
    V1_ERROR_END = V1_ERROR_START - 30,

    /* Base error code */
    ERROR_BASE = -200000,

    /* Error code representing invalid input parameters */
    ERROR_INVALID_INPUT_PARAMETERS = ERROR_BASE - 1,

    /* Error code representing not context */
    ERROR_NO_CONTEXT = ERROR_BASE - 2,

    /* Error code representing entity is busy */
    ERROR_ENTITY_BUSY = ERROR_BASE - 3,

    /* Error code representing fail to generate a command */
    ERROR_GENERATE_COMMAND_FAILED = ERROR_BASE - 4,

    /* Error code representing fail to post data */
    ERROR_POST_DATA_FAILED = ERROR_BASE - 5,

    /* Error code representing wait link state change timeout */
    ERROR_WAIT_LINK_CHANGE_TIMEOUT = ERROR_BASE - 6,

    /* Error code representing reuse link fail */
    ERROR_SINK_REUSE_LINK_FAILED = ERROR_BASE - 7,

    /* Error code representing remove link fail */
    ERROR_REMOVE_LINK_FAILED = ERROR_BASE - 8,

    /* Error code representing fail to config Ip */
    ERROR_CONFIG_IP_FAIL = ERROR_BASE - 9,

    /* Error code representing no interface info on sink end */
    ERROR_SINK_NO_INTERFACE_INFO = ERROR_BASE - 10,

    /* Error code representing fail to reuse link on source end */
    ERROR_SOURCE_REUSE_LINK_FAILED = ERROR_BASE - 11,

    /* Error code representing no interface info on source end */
    ERROR_SOURCE_NO_INTERFACE_INFO = ERROR_BASE - 12,

    /* Error code representing no link on source end */
    ERROR_SOURCE_NO_LINK = ERROR_BASE - 13,

    /* Error code representing no link on sink end */
    ERROR_SINK_NO_LINK = ERROR_BASE - 14,

    /* Error code representing manager is busy */
    ERROR_MANAGER_BUSY = ERROR_BASE - 15,

    /* Error code representing information on auth connection is wrong */
    ERROR_WRONG_AUTH_CONNECTION_INFO = ERROR_BASE - 16,

    /* Error code representing start position of wifi direct errors */
    ERROR_WIFI_DIRECT_START = ERROR_BASE - 4000,

    /* Error code representing no suitable wifi direct processor */
    ERROR_WIFI_DIRECT_NO_SUITABLE_PROCESSOR = ERROR_BASE - 4001,

    /* Error code representing failed to process wifi direct command */
    ERROR_WIFI_DIRECT_PROCESS_FAILED = ERROR_BASE - 4002,

    /* Error code representing wrong wifi direct negotiation msg */
    ERROR_WIFI_DIRECT_WRONG_NEGOTIATION_MSG = ERROR_BASE - 4003,

    /* Error code representing wifi if off */
    ERROR_WIFI_OFF = ERROR_BASE - 4004,

    /* Error code representing rpt is enabled */
    ERROR_RPT_ENABLED = ERROR_BASE - 4005,

    /* Error code representing no suitable protocol */
    ERROR_WIFI_DIRECT_NO_SUITABLE_PROTOCOL = ERROR_BASE - 4006,

    /* Error code representing fail to pack data */
    ERROR_WIFI_DIRECT_PACK_DATA_FAILED = ERROR_BASE - 4007,

    /* Error code representing wait negotiation message timeout */
    ERROR_WIFI_DIRECT_WAIT_NEGOTIATION_MSG_TIMEOUT = ERROR_BASE - 4008,

    /* Error code representing wait connect request timeout */
    ERROR_WIFI_DIRECT_WAIT_CONNECT_REQUEST_TIMEOUT = ERROR_BASE - 4009,

    /* Error code representing wait connect response timeout */
    ERROR_WIFI_DIRECT_WAIT_CONNECT_RESPONSE_TIMEOUT = ERROR_BASE - 4010,

    /* Error code representing fail to get LinkInfo on sink end */
    ERROR_WIFI_DIRECT_SINK_GET_LINK_INFO_FAILED = ERROR_BASE - 4011,

    /* Error code representing fail to get remote wifi config info */
    ERROR_WIFI_DIRECT_GET_REMOTE_WIFI_CFG_INFO_FAILED = ERROR_BASE - 4012,

    /* Error code representing fail to get local wifi config info */
    ERROR_WIFI_DIRECT_SINK_GET_LOCAL_WIFI_CFG_INFO_FAILED = ERROR_BASE - 4013,

    /* Error code representing fail to get LinkInfo on source end */
    ERROR_WIFI_DIRECT_SOURCE_GET_LINK_INFO_FAILED = ERROR_BASE - 4014,

    /* Error code representing fail to set connect notify */
    ERROR_WIFI_DIRECT_SET_CONNECT_NOTIFY_FAILED = ERROR_BASE - 4015,

    /* Error code representing local link is not connected, but remote link is still connected */
    ERROR_WIFI_DIRECT_LOCAL_DISCONNECTED_REMOTE_CONNECTED = ERROR_BASE - 4016,

    /* Error code representing local link is connected, but remote link is not connected */
    ERROR_WIFI_DIRECT_LOCAL_CONNECTED_REMOTE_DISCONNECTED = ERROR_BASE - 4017,

    /* Error code representing two devices initiate a connection or a disconnection to peer device simultaneously */
    ERROR_WIFI_DIRECT_BIDIRECTIONAL_SIMULTANEOUS_REQ = ERROR_BASE - 4018,

    /* Error code representing there exists no available interface */
    ERROR_WIFI_DIRECT_NO_AVAILABLE_INTERFACE = ERROR_BASE - 4019,

    /* Error code representing remote device is not trusted */
    ERROR_WIFI_DIRECT_NOT_TRUSTED_DEVICE = ERROR_BASE - 4020,

    /* Error code representing remote device is not trusted */
    ERROR_WIFI_DIRECT_UNPACK_DATA_FAILED = ERROR_BASE - 4021,

    /* Error code representing command wait timeout */
    ERROR_WIFI_DIRECT_COMMAND_WAIT_TIMEOUT = ERROR_BASE - 4022,

    /* Error code representing wait connect reuse response timeout */
    ERROR_WIFI_DIRECT_WAIT_REUSE_RESPONSE_TIMEOUT = ERROR_BASE - 4023,

    /* Error code representing p2p link is used by another service */
    ERROR_P2P_LINK_USED_BY_ANOTHER_SERVICE = ERROR_BASE - 5000,

    /* Error code representing mismatch role */
    ERROR_P2P_GC_AVAILABLE_WITH_MISMATCHED_ROLE = ERROR_BASE - 5001,

    /* Error code representing current GC device has connected to another device */
    ERROR_P2P_GC_CONNECTED_TO_ANOTHER_DEVICE = ERROR_BASE - 5002,

    /* Error code representing the GO is not a trusted device */
    ERROR_P2P_GO_NOT_TRUSTED = ERROR_BASE - 5003,

    /* Error code representing fail to apply GC ip address */
    ERROR_P2P_APPLY_GC_IP_FAIL = ERROR_BASE - 5004,

    /* Error code representing p2p server has already destroyed */
    ERROR_P2P_SERVER_ALREADY_DESTROYED = ERROR_BASE - 5005,

    /* Error code representing two devices are both GO */
    ERROR_P2P_BOTH_GO = ERROR_BASE - 5006,

    /* Error code representing remote GC device has connected to another GO */
    ERROR_P2P_PEER_GC_CONNECTED_TO_ANOTHER_DEVICE = ERROR_BASE - 5007,

    /* Error code representing GO available with mismatched role */
    ERROR_P2P_GO_AVAILABLE_WITH_MISMATCHED_ROLE = ERROR_BASE - 5008,

    /* Error code representing fail to remove link */
    ERROR_P2P_SHARE_LINK_REMOVE_FAILED = ERROR_BASE - 5009,

    /* Error code representing fail to reuse link */
    ERROR_P2P_SHARE_LINK_REUSE_FAILED = ERROR_BASE - 5010,

    /* Error code representing handling an expired request */
    ERROR_P2P_EXPIRED_REQ = ERROR_BASE - 5011,

    /* Error code representing handling an expired response */
    ERROR_P2P_EXPIRED_RESP = ERROR_BASE - 5012,

    /* Error code representing fail to connect group */
    ERROR_P2P_CONNECT_GROUP_FAILED = ERROR_BASE - 5200,

    /* Error code representing p2p client already exists */
    ERROR_P2P_CLIENT_EXISTS = ERROR_BASE - 5201,

    /* Error code representing fail to create p2p group */
    ERROR_P2P_CREATE_GROUP_FAILED = ERROR_BASE - 5600,

    /* Error code representing p2p server already exists */
    ERROR_P2P_SERVER_EXISTS = ERROR_BASE - 5601,

    /* Error code representing fail disconnect hml */
    ERROR_HML_DISCONNECT_FAIL = ERROR_BASE - 6000,

    /* Error code representing config ip fail */
    ERROR_HML_CONFIG_IP_FAIL = ERROR_BASE - 6001,

    /* Error code representing apply ip fail */
    ERROR_HML_APPLY_IP_FAIL = ERROR_BASE - 6002,

    /* Error code representing fail to connect hml group */
    ERROR_HML_CONNECT_GROUP_FAIL = ERROR_BASE - 6200,

    /* Error code representing fail to create hml group */
    ERROR_HML_CREATE_GROUP_FAIL = ERROR_BASE - 6600,

    /* Error code representing fail to destroy hml group */
    ERROR_HML_DESTROY_FAIL = ERROR_BASE - 6601,

    /* Error code representing fail to notify connect */
    ERROR_HML_CONNECT_NOTIFY_FAIL = ERROR_BASE - 6602,

    /* Error code representing 3 vap conflict */
    ERROR_LOCAL_THREE_VAP_CONFLICT = ERROR_BASE - 6603,

    /* Error code representing Peer device 3 vap conflict */
    ERROR_PEER_THREE_VAP_CONFLICT = ERROR_BASE - 6604,

    /* Error code representing Local device 3 vap dbac conflict */
    ERROR_LOCAL_THREE_VAP_DBAC_CONFLICT = ERROR_BASE - 6605,

    /* Error code representing Peer device 3 vap dbac conflict */
    ERROR_PEER_THREE_VAP_DBAC_CONFLICT = ERROR_BASE - 6606,

    /* Error code representing Entity is unavailable */
    ERROR_ENTITY_UNAVAILABLE = ERROR_BASE - 6607,

    /* Error code representing remote client join failed */
    ERROR_HML_CLIENT_JOIN_FAIL = ERROR_BASE - 6608,

    /* Error code representing switch notify failed */
    ERROR_HML_SWITCH_NOTIFY_FAIL = ERROR_BASE - 6609,

    /* Error code representing switch notify failed */
    ERROR_HML_RENEGO_TO_P2P = ERROR_BASE - 6610,

    /* Error code representing waiting hand shake timeout */
    ERROR_HML_WAITING_HANDSHAKE_TIMEOUT = ERROR_BASE - 6611,

    /* Error code wait HML_CREATE_GROUP timeout */
    ERROR_HML_CREATE_GROUP_TIMEOUT = ERROR_BASE - 6612,

    /* Error code wait HML_DESTROY_GROUP timeout */
    ERROR_HML_DESTROY_GROUP_TIMEOUT = ERROR_BASE - 6613,

    /* Error code wait HML_CONN_NOTIFY timeout */
    ERROR_HML_CONN_NOTIFY_TIMEOUT = ERROR_BASE - 6614,

    /* Error code wait HML_CONNECT_GROUP timeout */
    ERROR_HML_CONNECT_GROUP_TIMEOUT = ERROR_BASE - 6615,

    /* Error code wait HML_DISCONNECT_GROUP timeout */
    ERROR_HML_DISCONNECT_GROUP_TIMEOUT = ERROR_BASE - 6616,

    /* Error code auth start listen failed */
    ERROR_HML_AUTH_START_LISTEN_FAIL = ERROR_BASE - 6617,

    /* Error code auth open connection failed */
    ERROR_HML_AUTH_OPEN_CONNECTION_FAIL = ERROR_BASE - 6618,

    /* Error code switch notify timeout */
    ERROR_HML_SWITCH_NOTIFY_TIMEOUT = ERROR_BASE - 6619,

    /* Error code need renegotiate */
    ERROR_HML_NEED_RENEGOTIATE = ERROR_BASE - 6620,

    /* Error code need renegotiate */
    ERROR_HML_PRE_ASSIGN_PORT_FAILED = ERROR_BASE - 6621,

    /* Error code no negotiate channel */
    ERROR_NO_NEGO_CHANNEL = ERROR_BASE - 6622,

    /* Error code parallelism conflict */
    ERROR_PARALLELISM_CONFLICT = ERROR_BASE - 6623,
    
    /* Error code retry for avoid block */
    ERROR_RETRY_FOR_AVOID_BLOCK = ERROR_BASE - 6624,
	
    /* Error code no wifi config info */
    ERROR_NO_WIFI_CONFIG_INFO = ERROR_BASE - 6625,

    /* Error code start action listen failed */
    ERROR_START_ACTION_LISTEN_FAILED = ERROR_BASE - 6626,

    /* Error code trigger message not handled */
    ERROR_TRIGGER_MSG_NOT_HANDLED = ERROR_BASE - 6627,

    /* Error code representing end position of wifi direct errors */
    ERROR_WIFI_DIRECT_END = ERROR_BASE - 6999,
};

static inline int32_t ToSoftBusErrorCode(int32_t errorCode)
{
    return SOFTBUS_ERRNO(SHORT_DISTANCE_MAPPING_MODULE_CODE) + abs(errorCode);
}

#ifdef __cplusplus
}
#endif
#endif
