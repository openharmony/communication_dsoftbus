/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

#include <stdio.h>

#include "br_proxy_error_code.h"
#include "softbus_error_code.h"

typedef struct {
    int32_t errorCode;
    const char *errorMessage;
} NapiSoftbusErrEntry;

typedef struct {
    int32_t cErrCode;
    int32_t jsErrCode;
} NapiSoftbusErrCMapJs;

const NapiSoftbusErrCMapJs ERRCODE_C_JS_MAP[] = {
    { SOFTBUS_ACCESS_TOKEN_DENIED,              COMMON_ACCESS_TOKEN_DENIED                      },
    { SOFTBUS_CONN_BR_DISABLE_ERR,              NAPI_SOFTBUS_LINK_DISABLED                      },
    { SOFTBUS_INVALID_PARAM,                    COMMON_INVALID_PARAM                            },
    { SOFTBUS_TRANS_INVALID_CHANNEL_ID,         NAPI_SOFTBUS_CHANNEL_UNAVAILABLE                },
    { SOFTBUS_CONN_OPEN_PROXY_TIMEOUT,          NAPI_SOFTBUS_OPEN_OPERATION_FAILED              },
    { SOFTBUS_TRANS_BR_PROXY_DATA_TOO_LONG,     NAPI_SOFTBUS_DATA_TOO_LONG                      },
    { SOFTBUS_TRANS_BR_PROXY_TOKENID_ERR,       NAPI_SOFTBUS_CALL_IS_RESTRICTED                 },
    { SOFTBUS_CONN_BR_UNDERLAY_WRITE_FAIL,      NAPI_SOFTBUS_SEND_OPERATION_FAILED              },
    { SOFTBUS_CONN_BR_UNDERLAY_CONNECT_FAIL,    NAPI_SOFTBUS_OPEN_OPERATION_FAILED              },
    { SOFTBUS_TRANS_BR_PROXY_CALLER_RESTRICTED, NAPI_SOFTBUS_CALL_IS_RESTRICTED                 },
    { SOFTBUS_CONN_BR_UNPAIRED,                 NAPI_SOFTBUS_DEVICE_NOT_PAIRED                  },
    { SOFTBUS_TRANS_SESSION_OPENING,            NAPI_SOFTBUS_CHANNEL_REOPEN                     },
    { SOFTBUS_TRANS_BR_PROXY_INVALID_PARAM,     NAPI_SOFTBUS_INVALID_PARAM                      },
};

const NapiSoftbusErrEntry ERRCODE_MSG_MAP[] = {
    { COMMON_ACCESS_TOKEN_DENIED,
        "BusinessError 201:Permission denied. need permission: ohos.permission.ACCESS_BLUETOOTH."                   },
    { COMMON_INVALID_PARAM,                         "BusinessError 401:Parameter error."                            },
    { NAPI_SOFTBUS_LINK_DISABLED,                   "BusinessError 32390001: BR is disabled."                       },
    { NAPI_SOFTBUS_DEVICE_NOT_PAIRED,               "BusinessError 32390002: Device not paired."                    },
    { NAPI_SOFTBUS_PROFILE_NOT_SUPPORT,             "BusinessError 32390003: Profile not supported"                 },
    { NAPI_SOFTBUS_CHANNEL_UNAVAILABLE,             "BusinessError 32390004: ChannelId is invalid or unavailable"   },
    { NAPI_SOFTBUS_CHANNEL_REOPEN,                  "BusinessError 32390005: The channel is repeatedly opened."     },
    { NAPI_SOFTBUS_INVALID_PARAM,                   "BusinessError 32390006: Parameter error."                      },
    { NAPI_SOFTBUS_INTERNAL_ERROR,                  "BusinessError 32390100: Internal error, It is can be ignored." },
    { NAPI_SOFTBUS_CALL_IS_RESTRICTED,              "BusinessError 32390101: Call is restricted."                   },
    { NAPI_SOFTBUS_OPEN_OPERATION_FAILED,
        "BusinessError 32390102: Operation failed or Connection timed out."                                         },
    { NAPI_SOFTBUS_DATA_TOO_LONG,                   "BusinessError 32390103: Data too long."                        },
    { NAPI_SOFTBUS_SEND_OPERATION_FAILED,           "BusinessError 32390104: Send failed."                          },
    { NAPI_SOFTBUS_UNKNOWN_ERR,                     "BusinessError 30200000: unknown error"                          },
};

const char *GetErrMsgByErrCode(int32_t errCode)
{
    size_t mapSize = sizeof(ERRCODE_MSG_MAP) / sizeof(ERRCODE_MSG_MAP[0]);
    for (size_t i = 0; i < mapSize; ++i) {
        if (ERRCODE_MSG_MAP[i].errorCode == errCode) {
            return ERRCODE_MSG_MAP[i].errorMessage;
        }
    }
    return NULL;
}

int32_t NapiTransConvertErr(int32_t err)
{
    size_t mapSize = sizeof(ERRCODE_C_JS_MAP) / sizeof(ERRCODE_C_JS_MAP[0]);
    for (size_t i = 0; i < mapSize; ++i) {
        if (err == ERRCODE_C_JS_MAP[i].cErrCode) {
            return ERRCODE_C_JS_MAP[i].jsErrCode;
        }
    }

    return NAPI_SOFTBUS_INTERNAL_ERROR;
}
