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

#define LNN_AUDIT_ASSIGNER(type, filedName, filed)                                                            \
    static inline bool LnnAuditAssigner##filedName(                                                           \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->lnnAuditExtra->filed, &param) && CopyString(param->name, eventName)) {       \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

LNN_AUDIT_ASSIGNER(Errcode, Errcode, errcode)
LNN_AUDIT_ASSIGNER(Int32, AuditType, auditType)
LNN_AUDIT_ASSIGNER(Int32, ConnectionId, connectionId)
LNN_AUDIT_ASSIGNER(Int32, AuthLinkType, authLinkType)
LNN_AUDIT_ASSIGNER(Int32, AuthId, authId)
LNN_AUDIT_ASSIGNER(Int32, OnlineNum, onlineNum)
LNN_AUDIT_ASSIGNER(String, PeerIp, peerIp)
LNN_AUDIT_ASSIGNER(String, PeerBrMac, peerBrMac)
LNN_AUDIT_ASSIGNER(String, PeerBleMac, peerBleMac)
LNN_AUDIT_ASSIGNER(String, PeerAuthPort, peerAuthPort)
LNN_AUDIT_ASSIGNER(String, PeerUdid, peerUdid)
LNN_AUDIT_ASSIGNER(String, PeerNetworkId, peerNetworkId)
LNN_AUDIT_ASSIGNER(String, PeerDeviceType, peerDeviceType)
LNN_AUDIT_ASSIGNER(String, CallerPkg, callerPkg)
LNN_AUDIT_ASSIGNER(String, CalleePkg, calleePkg)

#define LNN_AUDIT_ASSIGNER_SIZE 19 // Size of g_connAssigners
static const HiSysEventParamAssigner g_lnnAuditAssigners[] = {
    { "ERROR_CODE",       HISYSEVENT_INT32,  LnnAuditAssignerErrcode          },
    { "AUDIT_TYPE",       HISYSEVENT_INT32,  LnnAuditAssignerAuditType        },
    { "CONN_ID",          HISYSEVENT_INT32,  LnnAuditAssignerConnectionId     },
    { "AUTH_LINK_TYPE",   HISYSEVENT_INT32,  LnnAuditAssignerAuthLinkType     },
    { "AUTH_ID",          HISYSEVENT_INT32,  LnnAuditAssignerAuthId           },
    { "ONLINE_NUM",       HISYSEVENT_INT32,  LnnAuditAssignerOnlineNum        },
    { "PEER_IP",          HISYSEVENT_STRING, LnnAuditAssignerPeerIp           },
    { "PEER_BR_MAC",      HISYSEVENT_STRING, LnnAuditAssignerPeerBrMac        },
    { "PEER_BLE_MAC",     HISYSEVENT_STRING, LnnAuditAssignerPeerBleMac       },
    { "PEER_AUTH_PORT",   HISYSEVENT_INT32,  LnnAuditAssignerPeerAuthPort     },
    { "PEER_UDID",        HISYSEVENT_STRING, LnnAuditAssignerPeerUdid         },
    { "PEER_NET_ID",      HISYSEVENT_STRING, LnnAuditAssignerPeerNetworkId    },
    { "PEER_DEV_TYPE",    HISYSEVENT_STRING,  LnnAuditAssignerPeerDeviceType   },
    { "HOST_PKG",         HISYSEVENT_STRING, LnnAuditAssignerCallerPkg        },
    { "TO_CALL_PKG",      HISYSEVENT_STRING, LnnAuditAssignerCalleePkg        },
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
#endif // LNN_EVENT_CONVERTER_H
