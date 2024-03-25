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

#ifndef LNN_AUDIT_CONVERTER_H
#define LNN_AUDIT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define LNN_AUDIT_ASSIGNER(type, fieldName, field)                                                            \
    static inline bool LnnAuditAssigner##fieldName(                                                           \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnAuditExtra->field, &param) &&                                             \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_AUDIT_ASSIGNER(Int32,   Result, result)
LNN_AUDIT_ASSIGNER(Errcode, ErrCode, errCode)
LNN_AUDIT_ASSIGNER(Int32,  AuditType, auditType)
LNN_AUDIT_ASSIGNER(Uint64, ConnectionId, connId)
LNN_AUDIT_ASSIGNER(Int32,  AuthLinkType, authLinkType)
LNN_AUDIT_ASSIGNER(Uint32, AuthRequestId, authRequestId)
LNN_AUDIT_ASSIGNER(Int32,  OnlineNum, onlineNum)
LNN_AUDIT_ASSIGNER(String, HostPkg, hostPkg)
LNN_AUDIT_ASSIGNER(String, LocalIp, localIp)
LNN_AUDIT_ASSIGNER(String, LocalBrMac, localBrMac)
LNN_AUDIT_ASSIGNER(String, LocalBleMac, localBleMac)
LNN_AUDIT_ASSIGNER(String, LocalUdid, localUdid)
LNN_AUDIT_ASSIGNER(String, LocalNetworkId, localNetworkId)
LNN_AUDIT_ASSIGNER(String, LocalDevName, localDevName)
LNN_AUDIT_ASSIGNER(String, PeerIp, peerIp)
LNN_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
LNN_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
LNN_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
LNN_AUDIT_ASSIGNER(String, PeerNetworkId, peerNetworkId)
LNN_AUDIT_ASSIGNER(String, PeerDevName, peerDevName)
LNN_AUDIT_ASSIGNER(Int32, LocalAuthPort, localAuthPort)
LNN_AUDIT_ASSIGNER(Int32, LocalProxyPort, localProxyPort)
LNN_AUDIT_ASSIGNER(Int32, LocalSessionPort, localSessionPort)
LNN_AUDIT_ASSIGNER(Int32, LocalDevType, localDevType)
LNN_AUDIT_ASSIGNER(Int32, PeerAuthPort, peerAuthPort)
LNN_AUDIT_ASSIGNER(Int32, PeerProxyPort, peerProxyPort)
LNN_AUDIT_ASSIGNER(Int32, PeerSessionPort, peerSessionPort)
LNN_AUDIT_ASSIGNER(Int32, PeerDevType, peerDevType)
LNN_AUDIT_ASSIGNER(Int32, AttackTimes, attackTimes)
LNN_AUDIT_ASSIGNER(Int32, BeAttackedPort, beAttackedPort)
LNN_AUDIT_ASSIGNER(Int32, HbEventType, hbEventType)

#define LNN_AUDIT_ASSIGNER_SIZE 31 // Size of g_lnnAuditAssigners
static const HiSysEventParamAssigner g_lnnAuditAssigners[] = {
    { "RESULT",               HISYSEVENT_INT32,  LnnAuditAssignerResult           },
    { "ERROR_CODE",           HISYSEVENT_INT32,  LnnAuditAssignerErrCode          },
    { "AUDIT_TYPE",           HISYSEVENT_INT32,  LnnAuditAssignerAuditType        },
    { "CONN_ID",              HISYSEVENT_UINT64, LnnAuditAssignerConnectionId     },
    { "AUTH_LINK_TYPE",       HISYSEVENT_INT32,  LnnAuditAssignerAuthLinkType     },
    { "AUTH_REQUEST_ID",      HISYSEVENT_UINT32, LnnAuditAssignerAuthRequestId    },
    { "ONLINE_NUM",           HISYSEVENT_INT32,  LnnAuditAssignerOnlineNum        },
    { "HOST_PKG",             HISYSEVENT_STRING, LnnAuditAssignerHostPkg          },
    { "LOCAL_IP",             HISYSEVENT_STRING, LnnAuditAssignerLocalIp          },
    { "LOCAL_BR_MAC",         HISYSEVENT_STRING, LnnAuditAssignerLocalBrMac       },
    { "LOCAL_BLE_MAC",        HISYSEVENT_STRING, LnnAuditAssignerLocalBleMac      },
    { "LOCAL_UDID",           HISYSEVENT_STRING, LnnAuditAssignerLocalUdid        },
    { "LOCAL_NETWORK_ID",     HISYSEVENT_STRING, LnnAuditAssignerLocalNetworkId   },
    { "LOCAL_DEV_NAME",       HISYSEVENT_STRING, LnnAuditAssignerLocalDevName     },
    { "PEER_IP",              HISYSEVENT_STRING, LnnAuditAssignerPeerIp           },
    { "PEER_BR_MAC",          HISYSEVENT_STRING, LnnAuditAssignerPeerBrMac        },
    { "PEER_BLE_MAC",         HISYSEVENT_STRING, LnnAuditAssignerPeerBleMac       },
    { "PEER_UDID",            HISYSEVENT_STRING, LnnAuditAssignerPeerUdid         },
    { "PEER_NETWORK_ID",      HISYSEVENT_STRING, LnnAuditAssignerPeerNetworkId    },
    { "PEER_DEV_NAME",        HISYSEVENT_STRING, LnnAuditAssignerPeerDevName      },
    { "LOCAL_AUTH_PORT",      HISYSEVENT_INT32,  LnnAuditAssignerLocalAuthPort    },
    { "LOCAL_PROXY_PORT",     HISYSEVENT_INT32,  LnnAuditAssignerLocalProxyPort   },
    { "LOCAL_SESSION_PORT",   HISYSEVENT_INT32,  LnnAuditAssignerLocalSessionPort },
    { "LOCAL_DEV_TYPE",       HISYSEVENT_INT32,  LnnAuditAssignerLocalDevType     },
    { "PEER_AUTH_PORT",       HISYSEVENT_INT32,  LnnAuditAssignerPeerAuthPort     },
    { "PEER_PROXY_PORT",      HISYSEVENT_INT32,  LnnAuditAssignerPeerProxyPort    },
    { "PEER_SESSION_PORT",    HISYSEVENT_INT32,  LnnAuditAssignerPeerSessionPort  },
    { "PEER_DEV_TYPE",        HISYSEVENT_INT32,  LnnAuditAssignerPeerDevType      },
    { "ATTACK_TIMES",         HISYSEVENT_INT32,  LnnAuditAssignerAttackTimes      },
    { "BE_ATTACKED_PORT",     HISYSEVENT_INT32,  LnnAuditAssignerBeAttackedPort   },
    { "HEARTBEAT_EVENT_TYPE", HISYSEVENT_INT32,  LnnAuditAssignerHbEventType      },
    // Modification Note: remember updating LNN_AUDIT_ASSIGNER_SIZE
};

static inline size_t ConvertLnnAuditForm2Param(HiSysEventParam params[], SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->lnnExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < sizeof(g_lnnAuditAssigners) / sizeof(g_lnnAuditAssigners[0]); ++i) {
        HiSysEventParamAssigner assigner = g_lnnAuditAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}
#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // LNN_AUDIT_CONVERTER_H
