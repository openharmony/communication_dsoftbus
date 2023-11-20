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

#ifndef DISC_EVENT_CONVERTER_H
#define DISC_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISC_ASSIGNER(type, filedName, filed)                                                                 \
    static inline bool DiscAssigner##filedName(                                                               \
        const char eventName[], HiSysEventParamType paramType, SoftbusEventForm form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form.discExtra.filed, &param) && CopyString(param->name, eventName)) {            \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

DISC_ASSIGNER(Int32, BroadcastType, broadcastType)
DISC_ASSIGNER(Int32, BroadcastFreq, broadcastFreq)
DISC_ASSIGNER(Int32, ScanType, scanType)
DISC_ASSIGNER(Int32, DiscMode, discMode)
DISC_ASSIGNER(Int32, DiscType, discType)
DISC_ASSIGNER(Int32, LocalNetworkId, localNetworkId)
DISC_ASSIGNER(Int32, LocalDeviceType, localDeviceType)
DISC_ASSIGNER(Int32, CostTime, costTime)
DISC_ASSIGNER(Int32, PeerNetworkId, peerNetworkId)
DISC_ASSIGNER(Int32, PeerDeviceType, peerDeviceType)
DISC_ASSIGNER(Int32, Result, result)
DISC_ASSIGNER(Errcode, Errcode, errcode)
DISC_ASSIGNER(String, CallerPkg, callerPkg)
DISC_ASSIGNER(String, ScanCycle, scanCycle)
DISC_ASSIGNER(String, PeerBrMac, peerBrMac)
DISC_ASSIGNER(String, PeerBleMac, peerBleMac)
DISC_ASSIGNER(String, PeerWifiMac, peerWifiMac)
DISC_ASSIGNER(String, PeerIp, peerIp)
DISC_ASSIGNER(String, PeerPort, peerPort)

#define DISC_ASSIGNER_SIZE 19 // Size of g_discAssigners
static HiSysEventParamAssigner g_discAssigners[] = {
    {"BROADCAST_TYPE",        HISYSEVENT_INT32,  DiscAssignerBroadcastType  },
    { "BROADCAST_FREQ",       HISYSEVENT_INT32,  DiscAssignerBroadcastFreq  },
    { "SCAN_TYPE",            HISYSEVENT_INT32,  DiscAssignerScanType       },
    { "DISC_MODE",            HISYSEVENT_INT32,  DiscAssignerDiscMode       },
    { "DISC_TYPE",            HISYSEVENT_INT32,  DiscAssignerDiscType       },
    { "LOCAL_NET_ID",         HISYSEVENT_INT32,  DiscAssignerLocalNetworkId },
    { "LOCAL_DEV_TYPE",       HISYSEVENT_INT32,  DiscAssignerLocalDeviceType},
    { "FIRST_DISCOVERY_TIME", HISYSEVENT_INT32,  DiscAssignerCostTime       },
    { "PEER_NETID",           HISYSEVENT_INT32,  DiscAssignerPeerNetworkId  },
    { "PEER_DEV_TYPE",        HISYSEVENT_INT32,  DiscAssignerPeerDeviceType },
    { "STAGE_RES",            HISYSEVENT_INT32,  DiscAssignerResult         },
    { "ERROR_CODE",           HISYSEVENT_INT32,  DiscAssignerErrcode        },
    { "HOST_PKG",             HISYSEVENT_STRING, DiscAssignerCallerPkg      },
    { "SCAN_CYCLE",           HISYSEVENT_STRING, DiscAssignerScanCycle      },
    { "PEER_BR_MAC",          HISYSEVENT_STRING, DiscAssignerPeerBrMac      },
    { "PEER_BLE_MAC",         HISYSEVENT_STRING, DiscAssignerPeerBleMac     },
    { "PEER_WIFI_MAC",        HISYSEVENT_STRING, DiscAssignerPeerWifiMac    },
    { "PEER_IP",              HISYSEVENT_STRING, DiscAssignerPeerIp         },
    { "PEER_PORT",            HISYSEVENT_STRING, DiscAssignerPeerPort       },
 // Modification Note: remember updating DISC_ASSIGNER_SIZE
};

static inline void ConvertDiscForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm form)
{
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_discAssigners[i];
        if (!assigner.Assign(assigner.name, assigner.type, form, &params[i])) {
            COMM_LOGE(COMM_DFX, "assign event fail, name=%s", assigner.name);
        }
    }
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_CONVERTER_H
