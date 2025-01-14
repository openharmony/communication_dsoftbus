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

#include "comm_log.h"
#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define DISC_ASSIGNER(type, fieldName, field)                                                                 \
    static inline bool DiscAssigner##fieldName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->discExtra->field, &param) &&                                                 \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

DISC_ASSIGNER(Errcode, Result, result)
DISC_ASSIGNER(Errcode, Errcode, errcode)
DISC_ASSIGNER(Int32, InitType, initType)
DISC_ASSIGNER(String, ServerType, serverType)
DISC_ASSIGNER(Int32, AdvHandle, advHandle)
DISC_ASSIGNER(Int32, BcOverMaxCnt, bcOverMaxCnt)
DISC_ASSIGNER(Int32, InterFuncType, interFuncType)
DISC_ASSIGNER(Int32, CapabilityBit, capabilityBit)
DISC_ASSIGNER(LongString, CapabilityData, capabilityData)
DISC_ASSIGNER(Int32, BleTurnState, bleTurnState)
DISC_ASSIGNER(Int32, IpLinkStatus, ipLinkStatus)
DISC_ASSIGNER(Int32, CoapChangeType, coapChangeType)
DISC_ASSIGNER(Int32, BroadcastType, broadcastType)
DISC_ASSIGNER(Int32, BroadcastFreq, broadcastFreq)
DISC_ASSIGNER(Int32, MinInterval, minInterval)
DISC_ASSIGNER(Int32, MaxInterval, maxInterval)
DISC_ASSIGNER(Int32, CurrentNum, currentNum)
DISC_ASSIGNER(Int32, ScanType, scanType)
DISC_ASSIGNER(Int32, ScanCount, scanCount)
DISC_ASSIGNER(String, ScanCycle, scanCycle)
DISC_ASSIGNER(Int32, DiscType, discType)
DISC_ASSIGNER(Int32, DiscMode, discMode)
DISC_ASSIGNER(Int32, SuccessCnt, successCnt)
DISC_ASSIGNER(Int32, FailCnt, failCnt)
DISC_ASSIGNER(Int32, StartTime, startTime)
DISC_ASSIGNER(Int32, CostTime, costTime)
DISC_ASSIGNER(AnonymizeString, LocalNetworkId, localNetworkId)
DISC_ASSIGNER(AnonymizeString, PeerIp, peerIp)
DISC_ASSIGNER(AnonymizeString, PeerBrMac, peerBrMac)
DISC_ASSIGNER(AnonymizeString, PeerBleMac, peerBleMac)
DISC_ASSIGNER(AnonymizeString, PeerWifiMac, peerWifiMac)
DISC_ASSIGNER(String, PeerPort, peerPort)
DISC_ASSIGNER(AnonymizeString, PeerNetworkId, peerNetworkId)
DISC_ASSIGNER(String, PeerDeviceType, peerDeviceType)
DISC_ASSIGNER(String, CallerPkg, callerPkg)

#define DISC_ASSIGNER_SIZE 35 // Size of g_discAssigners
static HiSysEventParamAssigner g_discAssigners[] = {
    { "STAGE_RES",            HISYSEVENT_INT32,  DiscAssignerResult         },
    { "ERROR_CODE",           HISYSEVENT_INT32,  DiscAssignerErrcode        },
    { "INIT_TYPE",            HISYSEVENT_INT32,  DiscAssignerInitType       },
    { "SERVER_TYPE",          HISYSEVENT_STRING, DiscAssignerServerType     },
    { "ADV_HANDLE",           HISYSEVENT_INT32,  DiscAssignerAdvHandle      },
    { "BC_OVERMAX_CNT",       HISYSEVENT_INT32,  DiscAssignerBcOverMaxCnt   },
    { "INTERFACE_FUNC_TYPE",  HISYSEVENT_INT32,  DiscAssignerInterFuncType  },
    { "CAPABILITY_BIT",       HISYSEVENT_INT32,  DiscAssignerCapabilityBit  },
    { "CAPABILITY_DATA",      HISYSEVENT_STRING, DiscAssignerCapabilityData },
    { "BLE_TURN_STATE",       HISYSEVENT_INT32,  DiscAssignerBleTurnState   },
    { "IP_LINK_STATUS",       HISYSEVENT_INT32,  DiscAssignerIpLinkStatus   },
    { "COAP_CHANGE_TYPE",     HISYSEVENT_INT32,  DiscAssignerCoapChangeType },
    { "BROADCAST_TYPE",       HISYSEVENT_INT32,  DiscAssignerBroadcastType  },
    { "BROADCAST_FREQ",       HISYSEVENT_INT32,  DiscAssignerBroadcastFreq  },
    { "MIN_INTERVAL",         HISYSEVENT_INT32,  DiscAssignerMinInterval    },
    { "MAX_INTERVAL",         HISYSEVENT_INT32,  DiscAssignerMaxInterval    },
    { "CURRENT_NUM",          HISYSEVENT_INT32,  DiscAssignerCurrentNum     },
    { "SCAN_TYPE",            HISYSEVENT_INT32,  DiscAssignerScanType       },
    { "SCAN_COUNT",           HISYSEVENT_INT32,  DiscAssignerScanCount      },
    { "SCAN_CYCLE",           HISYSEVENT_STRING, DiscAssignerScanCycle      },
    { "DISC_TYPE",            HISYSEVENT_INT32,  DiscAssignerDiscType       },
    { "DISC_MODE",            HISYSEVENT_INT32,  DiscAssignerDiscMode       },
    { "SUCCESS_CNT",          HISYSEVENT_INT32,  DiscAssignerSuccessCnt     },
    { "FAIL_CNT",             HISYSEVENT_INT32,  DiscAssignerFailCnt        },
    { "START_TIME",           HISYSEVENT_INT32,  DiscAssignerStartTime      },
    { "COST_TIME",            HISYSEVENT_INT32,  DiscAssignerCostTime       },
    { "LOCAL_NET_ID",         HISYSEVENT_STRING, DiscAssignerLocalNetworkId },
    { "PEER_IP",              HISYSEVENT_STRING, DiscAssignerPeerIp         },
    { "PEER_BR_MAC",          HISYSEVENT_STRING, DiscAssignerPeerBrMac      },
    { "PEER_BLE_MAC",         HISYSEVENT_STRING, DiscAssignerPeerBleMac     },
    { "PEER_WIFI_MAC",        HISYSEVENT_STRING, DiscAssignerPeerWifiMac    },
    { "PEER_PORT",            HISYSEVENT_INT32,  DiscAssignerPeerPort       },
    { "PEER_NET_ID",          HISYSEVENT_STRING, DiscAssignerPeerNetworkId  },
    { "PEER_DEV_TYPE",        HISYSEVENT_STRING, DiscAssignerPeerDeviceType },
    { "HOST_PKG",             HISYSEVENT_STRING, DiscAssignerCallerPkg      },
    // Modification Note: remember updating DISC_ASSIGNER_SIZE
};

#define DISC_ALARM_ASSIGNER(type, fieldName, field)                                                           \
    static inline bool DiscAssigner##fieldName(                                                               \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->discAlarmExtra->field, &param) &&                                            \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

DISC_ALARM_ASSIGNER(Errcode, AlarmResult, result)
DISC_ALARM_ASSIGNER(Errcode, AlarmErrcode, errcode)
DISC_ALARM_ASSIGNER(Int32, OriginalFreq, originalFreq)
DISC_ALARM_ASSIGNER(Int32, AbnormalFreq, abnormalFreq)
DISC_ALARM_ASSIGNER(Int32, Duration, duration)

#define DISC_ALARM_ASSIGNER_SIZE 5 // Size of g_discAlarmAssigners
static const HiSysEventParamAssigner g_discAlarmAssigners[] = {
    { "STAGE_RES",        HISYSEVENT_INT32,  DiscAssignerAlarmResult     },
    { "ERROR_CODE",       HISYSEVENT_INT32,  DiscAssignerAlarmErrcode    },
    { "ORIGINAL_FREQ",    HISYSEVENT_INT32,  DiscAssignerOriginalFreq    },
    { "ABNORMAL_FREQ",    HISYSEVENT_INT32,  DiscAssignerAbnormalFreq    },
    { "DURATION",         HISYSEVENT_INT32,  DiscAssignerDuration        },
    // Modification Note: remember updating LNN_ALARM_ASSIGNER_SIZE
};

static inline size_t ConvertDiscForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(form != NULL && form->discExtra != NULL, validSize, COMM_DFX, "invalid param");
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_discAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

static inline size_t ConvertDiscAlarmForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    COMM_CHECK_AND_RETURN_RET_LOGE(form != NULL && form->discAlarmExtra != NULL, validSize, COMM_DFX, "invalid param");
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_discAlarmAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // DISC_EVENT_CONVERTER_H
