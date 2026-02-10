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

#ifndef TRANS_EVENT_CONVERTER_H
#define TRANS_EVENT_CONVERTER_H

#include "softbus_event_converter.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TRANS_ASSIGNER(type, fieldName, field)                                                                \
    static inline bool TransAssigner##fieldName(                                                              \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->transExtra->field, &param) &&                                                \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

TRANS_ASSIGNER(Uint8, TalkieFreq, talkieFreq)
TRANS_ASSIGNER(Uint8, TalkieType, talkieType)
TRANS_ASSIGNER(Uint8, TalkieLevel, talkieLevel)
TRANS_ASSIGNER(Errcode, Result, result)
TRANS_ASSIGNER(Errcode, Errcode, errcode)
TRANS_ASSIGNER(AnonymizeString, SocketName, socketName)
TRANS_ASSIGNER(Int32, DataType, dataType)
TRANS_ASSIGNER(Int32, ChannelType, channelType)
TRANS_ASSIGNER(Int32, LaneId, laneId)
TRANS_ASSIGNER(Int32, PreferLinkType, preferLinkType)
TRANS_ASSIGNER(Int32, LaneTransType, laneTransType)
TRANS_ASSIGNER(Int32, ChannelId, channelId)
TRANS_ASSIGNER(Int32, RequestId, requestId)
TRANS_ASSIGNER(Int32, ConnectionId, connectionId)
TRANS_ASSIGNER(Int32, LinkType, linkType)
TRANS_ASSIGNER(Int32, AuthId, authId)
TRANS_ASSIGNER(Int32, SocketFd, socketFd)
TRANS_ASSIGNER(Int32, CostTime, costTime)
TRANS_ASSIGNER(Int32, ChannelScore, channelScore)
TRANS_ASSIGNER(Int32, PeerChannelId, peerChannelId)
TRANS_ASSIGNER(Int32, BtFlow, btFlow)
TRANS_ASSIGNER(Int32, PagingId, pagingId)
TRANS_ASSIGNER(Int32, CallPid, callPid)
TRANS_ASSIGNER(Int32, SaId, saId)
TRANS_ASSIGNER(Int32,  BusinessFlag, businessFlag)
TRANS_ASSIGNER(String, GroupId, groupId)
TRANS_ASSIGNER(String, SubGroupId, subGroupId)
TRANS_ASSIGNER(AnonymizeString, PeerNetworkId, peerNetworkId)
TRANS_ASSIGNER(AnonymizeString, PeerUdid, peerUdid)
TRANS_ASSIGNER(String, PeerDevVer, peerDevVer)
TRANS_ASSIGNER(AnonymizeString, LocalUdid, localUdid)
TRANS_ASSIGNER(String, CallerPkg, callerPkg)
TRANS_ASSIGNER(String, CalleePkg, calleePkg)
TRANS_ASSIGNER(String, FirstTokenName, firstTokenName)
TRANS_ASSIGNER(AnonymizeString, CallerAccountId, callerAccountId)
TRANS_ASSIGNER(AnonymizeString, CalleeAccountId, calleeAccountId)
TRANS_ASSIGNER(Uint64, FirstTokenId, firstTokenId)
TRANS_ASSIGNER(Int32,  FirstTokenType, firstTokenType)
TRANS_ASSIGNER(LongString,  TrafficStats, trafficStats)
TRANS_ASSIGNER(Int32,  OsType, osType)
TRANS_ASSIGNER(Int32,  DeviceState, deviceState)
TRANS_ASSIGNER(Int32,  BusinessId, businessId)
TRANS_ASSIGNER(Int32,  BusinessType, businessType)
TRANS_ASSIGNER(Int32,  SessionId, sessionId)
TRANS_ASSIGNER(Int32,  MinBW, minBW)
TRANS_ASSIGNER(Int32,  MaxLatency, maxLatency)
TRANS_ASSIGNER(Int32,  MinLatency, minLatency)
TRANS_ASSIGNER(Uint16,  LocalStaChload, localStaChload)
TRANS_ASSIGNER(Uint16,  RemoteStaChload, remoteStaChload)
TRANS_ASSIGNER(Uint16,  LocalHmlChload, localHmlChload)
TRANS_ASSIGNER(Uint16,  RemoteHmlChload, remoteHmlChload)
TRANS_ASSIGNER(Uint16,  LocalP2pChload, localP2pChload)
TRANS_ASSIGNER(Uint16,  RemoteP2pChload, remoteP2pChload)
TRANS_ASSIGNER(Uint8,  LocalStaChannel, localStaChannel)
TRANS_ASSIGNER(Uint8,  RemoteStaChannel, remoteStaChannel)
TRANS_ASSIGNER(Uint8,  HmlChannel, hmlChannel)
TRANS_ASSIGNER(Uint8,  LocalP2pChannel, localP2pChannel)
TRANS_ASSIGNER(Uint8,  RemoteP2pChannel, remoteP2pChannel)
TRANS_ASSIGNER(Int32,  LocalIsDbac, localIsDbac)
TRANS_ASSIGNER(Int32,  RemoteIsDbac, remoteIsDbac)
TRANS_ASSIGNER(Int32,  LocalIsDbdc, localIsDbdc)
TRANS_ASSIGNER(Int32,  RemoteIsDbdc, remoteIsDbdc)
TRANS_ASSIGNER(String, ConCurrentId, conCurrentId)
TRANS_ASSIGNER(Int32,  MultipathTag, multipathTag)
TRANS_ASSIGNER(Int32,  FileRate, fileRate)
TRANS_ASSIGNER(Int32,  FileWirelessRate, fileWirelessRate)
TRANS_ASSIGNER(Int32,  FileWiredRate, fileWiredRate)
TRANS_ASSIGNER(Int32,  BytesRate, bytesRate)
TRANS_ASSIGNER(Int32,  FileChannelCnt, fileChannelCnt)
TRANS_ASSIGNER(Int32,  StreamChannelCnt, streamChannelCnt)
TRANS_ASSIGNER(Int32,  DataLen, dataLen)
TRANS_ASSIGNER(Uint64,  SessionDuration, sessionDuration)
TRANS_ASSIGNER(Uint8, ChannelStatus, channelStatus)
TRANS_ASSIGNER(Errcode,  UserId, userId)
TRANS_ASSIGNER(Errcode,  AppIndex, appIndex)

#define TRANS_ASSIGNER_SIZE 75 // Size of TRANS_ASSIGNERS
static const HiSysEventParamAssigner TRANS_ASSIGNERS[] = {
    { "TALKIE_FREQ",         HISYSEVENT_UINT8,    TransAssignerTalkieFreq      },
    { "TALKIE_TYPE",         HISYSEVENT_UINT8,    TransAssignerTalkieType      },
    { "TALKIE_LEVEL",        HISYSEVENT_UINT8,    TransAssignerTalkieLevel     },
    { "STAGE_RES",           HISYSEVENT_INT32,    TransAssignerResult          },
    { "ERROR_CODE",          HISYSEVENT_INT32,    TransAssignerErrcode         },
    { "SOCKET_NAME",         HISYSEVENT_STRING,   TransAssignerSocketName      },
    { "DATA_TYPE",           HISYSEVENT_INT32,    TransAssignerDataType        },
    { "LOGIC_CHAN_TYPE",     HISYSEVENT_INT32,    TransAssignerChannelType     },
    { "LANE_ID",             HISYSEVENT_INT32,    TransAssignerLaneId          },
    { "PREFER_LINK_TYPE",    HISYSEVENT_INT32,    TransAssignerPreferLinkType  },
    { "LANE_TRANS_TYPE",     HISYSEVENT_INT32,    TransAssignerLaneTransType   },
    { "CHAN_ID",             HISYSEVENT_INT32,    TransAssignerChannelId       },
    { "REQ_ID",              HISYSEVENT_INT32,    TransAssignerRequestId       },
    { "CONN_ID",             HISYSEVENT_INT32,    TransAssignerConnectionId    },
    { "LINK_TYPE",           HISYSEVENT_INT32,    TransAssignerLinkType        },
    { "AUTH_ID",             HISYSEVENT_INT32,    TransAssignerAuthId          },
    { "SOCKET_FD",           HISYSEVENT_INT32,    TransAssignerSocketFd        },
    { "COST_TIME",           HISYSEVENT_INT32,    TransAssignerCostTime        },
    { "CHAN_SCORE",          HISYSEVENT_INT32,    TransAssignerChannelScore    },
    { "PEER_CHAN_ID",        HISYSEVENT_INT32,    TransAssignerPeerChannelId   },
    { "BT_FLOW",             HISYSEVENT_INT32,    TransAssignerBtFlow          },
    { "PAGING_ID",           HISYSEVENT_INT32,    TransAssignerPagingId        },
    { "CALLER_PID",          HISYSEVENT_INT32,    TransAssignerCallPid         },
    { "SA_ID",               HISYSEVENT_INT32,    TransAssignerSaId            },
    { "BUSINESS_FLAG",       HISYSEVENT_INT32,    TransAssignerBusinessFlag    },
    { "GROUP_ID",            HISYSEVENT_STRING,   TransAssignerGroupId         },
    { "SUB_GROUP_ID",        HISYSEVENT_STRING,   TransAssignerSubGroupId      },
    { "PEER_NET_ID",         HISYSEVENT_STRING,   TransAssignerPeerNetworkId   },
    { "PEER_UDID",           HISYSEVENT_STRING,   TransAssignerPeerUdid        },
    { "PEER_DEV_VER",        HISYSEVENT_STRING,   TransAssignerPeerDevVer      },
    { "LOCAL_UDID",          HISYSEVENT_STRING,   TransAssignerLocalUdid       },
    { "HOST_PKG",            HISYSEVENT_STRING,   TransAssignerCallerPkg       },
    { "TO_CALL_PKG",         HISYSEVENT_STRING,   TransAssignerCalleePkg       },
    { "FIRST_TOKEN_NAME",    HISYSEVENT_STRING,   TransAssignerFirstTokenName  },
    { "CALLER_ACCOUNT_ID",   HISYSEVENT_STRING,   TransAssignerCallerAccountId },
    { "CALLEE_ACCOUNT_ID",   HISYSEVENT_STRING,   TransAssignerCalleeAccountId },
    { "FIRST_TOKEN_ID",      HISYSEVENT_UINT64,   TransAssignerFirstTokenId    },
    { "FIRST_TOKEN_TYPE",    HISYSEVENT_INT32,    TransAssignerFirstTokenType  },
    { "TRAFFIC_STATS",       HISYSEVENT_STRING,   TransAssignerTrafficStats    },
    { "OS_TYPE",             HISYSEVENT_INT32,    TransAssignerOsType          },
    { "DEVICE_STATE",        HISYSEVENT_INT32,    TransAssignerDeviceState     },
    { "BUSINESS_ID",         HISYSEVENT_INT32,    TransAssignerBusinessId      },
    { "BUSINESS_TYPE",       HISYSEVENT_INT32,    TransAssignerBusinessType    },
    { "SESSION_ID",          HISYSEVENT_INT32,    TransAssignerSessionId       },
    { "MIN_BW",              HISYSEVENT_INT32,    TransAssignerMinBW           },
    { "MAX_LATENCY",         HISYSEVENT_INT32,    TransAssignerMaxLatency      },
    { "MIN_LATENCY",         HISYSEVENT_INT32,    TransAssignerMinLatency      },
    { "LOCAL_STA_CHLOAD",    HISYSEVENT_UINT16,   TransAssignerLocalStaChload  },
    { "REMOTE_STA_CHLOAD",   HISYSEVENT_UINT16,   TransAssignerRemoteStaChload },
    { "LOCAL_HML_CHLOAD",    HISYSEVENT_UINT16,   TransAssignerLocalHmlChload  },
    { "REMOTE_HML_CHLOAD",   HISYSEVENT_UINT16,   TransAssignerRemoteHmlChload },
    { "LOCAL_P2P_CHLOAD",    HISYSEVENT_UINT16,   TransAssignerLocalP2pChload  },
    { "REMOTE_P2P_CHLOAD",   HISYSEVENT_UINT16,   TransAssignerRemoteP2pChload },
    { "LOCAL_STA_CHANNEL",   HISYSEVENT_UINT8,    TransAssignerLocalStaChannel },
    { "REMOTE_STA_CHANNEL",  HISYSEVENT_UINT8,    TransAssignerRemoteStaChannel},
    { "HML_CHANNEL",         HISYSEVENT_UINT8,    TransAssignerHmlChannel      },
    { "LOCAL_P2P_CHANNEL",   HISYSEVENT_UINT8,    TransAssignerLocalP2pChannel },
    { "REMOTE_P2P_CHANNEL",  HISYSEVENT_UINT8,    TransAssignerRemoteP2pChannel},
    { "LOCAL_IS_DBAC",       HISYSEVENT_INT32,    TransAssignerLocalIsDbac     },
    { "REMOTE_IS_DBAC",      HISYSEVENT_INT32,    TransAssignerRemoteIsDbac    },
    { "LOCAL_IS_DBDC",       HISYSEVENT_INT32,    TransAssignerLocalIsDbdc     },
    { "REMOTE_IS_DBDC",      HISYSEVENT_INT32,    TransAssignerRemoteIsDbdc    },
    { "CONCURRENT_ID",       HISYSEVENT_STRING,   TransAssignerConCurrentId    },
    { "MULTIPATH_TAG",       HISYSEVENT_INT32,    TransAssignerMultipathTag    },
    { "FILE_RATE",           HISYSEVENT_INT32,    TransAssignerFileRate        },
    { "FILE_WIRELESS_RATE",  HISYSEVENT_INT32,    TransAssignerFileWirelessRate},
    { "FILE_WIRED_RATE",     HISYSEVENT_INT32,    TransAssignerFileWiredRate   },
    { "BYTES_RATE",          HISYSEVENT_INT32,    TransAssignerBytesRate       },
    { "FILE_CHANNEL_CNT",    HISYSEVENT_INT32,    TransAssignerFileChannelCnt  },
    { "STREAM_CHANNEL_CNT",  HISYSEVENT_INT32,    TransAssignerStreamChannelCnt},
    { "DATA_LEN",            HISYSEVENT_INT32,    TransAssignerDataLen         },
    { "SESSION_DURATION",    HISYSEVENT_UINT64,   TransAssignerSessionDuration },
    { "CHANNEL_STATUS",      HISYSEVENT_UINT8,    TransAssignerChannelStatus   },
    { "USER_ID",             HISYSEVENT_INT32,    TransAssignerUserId          },
    { "APP_INDEX",           HISYSEVENT_INT32,    TransAssignerAppIndex        },
    // Modification Note: remember updating TRANS_ASSIGNER_SIZE
};

#define TRANS_ALARM_ASSIGNER(type, fieldName, field)                                                          \
    static inline bool TransAssigner##fieldName(                                                              \
        const char *eventName, HiSysEventParamType paramType, SoftbusEventForm *form, HiSysEventParam *param) \
    {                                                                                                         \
        if (Assigner##type(form->transAlarmExtra->field, &param) &&                                           \
            CopyString(param->name, eventName, MAX_LENGTH_OF_PARAM_NAME)) {                                   \
            param->t = paramType;                                                                             \
            return true;                                                                                      \
        }                                                                                                     \
        return false;                                                                                         \
    }

TRANS_ALARM_ASSIGNER(Errcode, AlarmResult, result)
TRANS_ALARM_ASSIGNER(Errcode, AlarmReason, errcode)
TRANS_ALARM_ASSIGNER(Int32, CallerPid, callerPid)
TRANS_ALARM_ASSIGNER(Int32, AlarmLinkType, linkType)
TRANS_ALARM_ASSIGNER(Int32, MinBw, minBw)
TRANS_ALARM_ASSIGNER(Int32, MethodId, methodId)
TRANS_ALARM_ASSIGNER(Int32, Duration, duration)
TRANS_ALARM_ASSIGNER(Int32, CurFlow, curFlow)
TRANS_ALARM_ASSIGNER(Int32, LimitFlow, limitFlow)
TRANS_ALARM_ASSIGNER(Int32, LimitTime, limitTime)
TRANS_ALARM_ASSIGNER(Int32, OccupyRes, occupyRes)
TRANS_ALARM_ASSIGNER(Int32, SyncType, syncType)
TRANS_ALARM_ASSIGNER(Int32, SyncData, syncData)
TRANS_ALARM_ASSIGNER(Int32, RetryCount, retryCount)
TRANS_ALARM_ASSIGNER(Int32, RetryReason, retryReason)
TRANS_ALARM_ASSIGNER(String, ConflictName, conflictName)
TRANS_ALARM_ASSIGNER(String, ConflictedName, conflictedName)
TRANS_ALARM_ASSIGNER(String, OccupyedName, occupyedName)
TRANS_ALARM_ASSIGNER(String, PermissionName, permissionName)
TRANS_ALARM_ASSIGNER(AnonymizeString, AlarmSessionName, sessionName)

#define TRANS_ALARM_ASSIGNER_SIZE 20 // Size of g_transAlarmAssigners
static const HiSysEventParamAssigner g_transAlarmAssigners[] = {
    { "STAGE_RES",         HISYSEVENT_INT32,  TransAssignerAlarmResult            },
    { "ERROR_CODE",        HISYSEVENT_INT32,  TransAssignerAlarmReason            },
    { "CALLER_PID",        HISYSEVENT_INT32,  TransAssignerCallerPid              },
    { "LINK_TYPE",         HISYSEVENT_INT32,  TransAssignerAlarmLinkType          },
    { "MIN_BW",            HISYSEVENT_INT32,  TransAssignerMinBw                  },
    { "METHOD_ID",         HISYSEVENT_INT32,  TransAssignerMethodId               },
    { "DURATION",          HISYSEVENT_INT32,  TransAssignerDuration               },
    { "CUR_FLOW",          HISYSEVENT_INT32,  TransAssignerCurFlow                },
    { "LIMIT_FLOW",        HISYSEVENT_INT32,  TransAssignerLimitFlow              },
    { "LIMIT_TIME",        HISYSEVENT_INT32,  TransAssignerLimitTime              },
    { "OCCUPY_RES",        HISYSEVENT_INT32,  TransAssignerOccupyRes              },
    { "SYNC_TYPE",         HISYSEVENT_INT32,  TransAssignerSyncType               },
    { "SYNC_DATA",         HISYSEVENT_INT32,  TransAssignerSyncData               },
    { "RETRY_COUNT",       HISYSEVENT_INT32,  TransAssignerRetryCount             },
    { "RETRY_REASON",      HISYSEVENT_INT32,  TransAssignerRetryReason            },
    { "CONFLICT_NAME",     HISYSEVENT_STRING, TransAssignerConflictName           },
    { "CONFLECTED_NAME",   HISYSEVENT_STRING, TransAssignerConflictedName         },
    { "OCCUPYED_NAME",     HISYSEVENT_STRING, TransAssignerOccupyedName           },
    { "PERMISSION_NAME",   HISYSEVENT_STRING, TransAssignerPermissionName         },
    { "SESSION_NAME",      HISYSEVENT_STRING,  TransAssignerAlarmSessionName      },
    // Modification Note: remember updating TRANS_ALARM_ASSIGNER_SIZE
};

static inline size_t ConvertTransForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->transExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = TRANS_ASSIGNERS[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

static inline size_t ConvertTransAlarmForm2Param(HiSysEventParam params[], size_t size, SoftbusEventForm *form)
{
    size_t validSize = 0;
    if (form == NULL || form->transAlarmExtra == NULL) {
        return validSize;
    }
    for (size_t i = 0; i < size; ++i) {
        HiSysEventParamAssigner assigner = g_transAlarmAssigners[i];
        if (assigner.Assign(assigner.name, assigner.type, form, &params[validSize])) {
            ++validSize;
        }
    }
    return validSize;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
#endif // TRANS_EVENT_CONVERTER_H
