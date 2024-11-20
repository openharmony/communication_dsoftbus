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

#ifndef TRANS_AUDIT_CONVERTER_H
#define TRANS_AUDIT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRANS_AUDIT_ASSIGNER(type, fieldName, field)                                                          \
    static inline bool TransAuditAssigner##fieldName(                                                         \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->transAuditExtra->field, &param) &&                                           \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

TRANS_AUDIT_ASSIGNER(String, HostPkg, hostPkg)
TRANS_AUDIT_ASSIGNER(Int32, Result, result)
TRANS_AUDIT_ASSIGNER(Errcode, Errcode, errcode)
TRANS_AUDIT_ASSIGNER(Int32, AuditType, auditType)
TRANS_AUDIT_ASSIGNER(String, LocalIp, localIp)
TRANS_AUDIT_ASSIGNER(String, LocalPort, localPort)
TRANS_AUDIT_ASSIGNER(String, LocalDevId, localDevId)
TRANS_AUDIT_ASSIGNER(Int32, LocalDevType, localDevType)
TRANS_AUDIT_ASSIGNER(String, LocalSessName, localSessName)
TRANS_AUDIT_ASSIGNER(Int32, LocalChannelId, localChannelId)
TRANS_AUDIT_ASSIGNER(String, PeerIp, peerIp)
TRANS_AUDIT_ASSIGNER(String, PeerPort, peerPort)
TRANS_AUDIT_ASSIGNER(String, PeerDevId, peerDevId)
TRANS_AUDIT_ASSIGNER(Int32, PeerDevType, peerDevType)
TRANS_AUDIT_ASSIGNER(String, PeerSessName, peerSessName)
TRANS_AUDIT_ASSIGNER(Int32, PeerChannelId, peerChannelId)
TRANS_AUDIT_ASSIGNER(Int32, ChannelType, channelType)
TRANS_AUDIT_ASSIGNER(Int32, AuthId, authId)
TRANS_AUDIT_ASSIGNER(Int32, ReqId, reqId)
TRANS_AUDIT_ASSIGNER(Int32, LinkType, linkType)
TRANS_AUDIT_ASSIGNER(Int32, ConnId, connId)
TRANS_AUDIT_ASSIGNER(Int32, SocketFd, socketFd)
TRANS_AUDIT_ASSIGNER(Int32, DataType, dataType)
TRANS_AUDIT_ASSIGNER(Int32, DataLen, dataLen)
TRANS_AUDIT_ASSIGNER(Int32, DataSeq, dataSeq)
TRANS_AUDIT_ASSIGNER(Int32, CostTime, costTime)
TRANS_AUDIT_ASSIGNER(Int32, DataTraffic, dataTraffic)
TRANS_AUDIT_ASSIGNER(Int32, ReqCount, reqCount)

#define TRANS_AUDIT_ASSIGNER_SIZE 28 // Size of g_transAuditAssigners
static const HiSysEventParamAssigner g_transAuditAssigners[] = {
    { "HOST_PKG",         HISYSEVENT_STRING, TransAuditAssignerHostPkg        },
    { "RESULT",           HISYSEVENT_INT32,  TransAuditAssignerResult         },
    { "ERROR_CODE",       HISYSEVENT_INT32,  TransAuditAssignerErrcode        },
    { "AUDIT_TYPE",       HISYSEVENT_INT32,  TransAuditAssignerAuditType      },
    { "LOCAL_IP",         HISYSEVENT_STRING, TransAuditAssignerLocalIp        },
    { "LOCAL_PORT",       HISYSEVENT_STRING, TransAuditAssignerLocalPort      },
    { "LOCAL_DEV_ID",     HISYSEVENT_STRING, TransAuditAssignerLocalDevId     },
    { "LOCAL_DEV_TYPE",   HISYSEVENT_INT32,  TransAuditAssignerLocalDevType   },
    { "LOCAL_SESS_NAME",  HISYSEVENT_STRING, TransAuditAssignerLocalSessName  },
    { "LOCAL_CHANNEL_ID", HISYSEVENT_INT32,  TransAuditAssignerLocalChannelId },
    { "PEER_IP",          HISYSEVENT_STRING, TransAuditAssignerPeerIp         },
    { "PEER_PORT",        HISYSEVENT_STRING, TransAuditAssignerPeerPort       },
    { "PEER_DEV_ID",      HISYSEVENT_STRING, TransAuditAssignerPeerDevId      },
    { "PEER_DEV_TYPE",    HISYSEVENT_INT32,  TransAuditAssignerPeerDevType    },
    { "PEER_SESS_NAME",   HISYSEVENT_STRING, TransAuditAssignerPeerSessName   },
    { "PEER_CHANNEL_ID",  HISYSEVENT_INT32,  TransAuditAssignerPeerChannelId  },
    { "CHANNEL_TYPE",     HISYSEVENT_INT32,  TransAuditAssignerChannelType    },
    { "AUTH_ID",          HISYSEVENT_INT32,  TransAuditAssignerAuthId         },
    { "REQ_ID",           HISYSEVENT_INT32,  TransAuditAssignerReqId          },
    { "LINK_TYPE",        HISYSEVENT_INT32,  TransAuditAssignerLinkType       },
    { "CONN_ID",          HISYSEVENT_INT32,  TransAuditAssignerConnId         },
    { "SOCKET_FD",        HISYSEVENT_INT32,  TransAuditAssignerSocketFd       },
    { "DATA_TYPE",        HISYSEVENT_INT32,  TransAuditAssignerDataType       },
    { "DATA_LEN",         HISYSEVENT_INT32,  TransAuditAssignerDataLen        },
    { "DATA_SEQ",         HISYSEVENT_INT32,  TransAuditAssignerDataSeq        },
    { "COST_TIME",        HISYSEVENT_INT32,  TransAuditAssignerCostTime       },
    { "DATA_TRAFFIC",     HISYSEVENT_INT32,  TransAuditAssignerDataTraffic    },
    { "REQ_COUNT",        HISYSEVENT_INT32,  TransAuditAssignerReqCount       },
    // Modification Note: remember updating TRANS_ASSIGNER_SIZE
};

static inline size_t ConvertTransAuditForm2Param(HiSysEventParam params[], SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->transExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < sizeof(g_transAuditAssigners) / sizeof(g_transAuditAssigners[i]); ++i) {
        HiSysEventParamAssigner assigner = g_transAuditAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_AUDIT_CONVERTER_H
