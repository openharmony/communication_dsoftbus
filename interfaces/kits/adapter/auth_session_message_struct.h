/*
* Copyright (c) 2022 Huawei Device Co., Ltd.
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

#ifndef AUTH_MESSAGE_STRUCT_H
#define AUTH_MESSAGE_STRUCT_H

#include <stdint.h>
#include "auth_interface_struct.h"

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif

typedef struct {
   const char *msg;
   uint32_t len;
   int32_t linkType;
   SoftBusVersion version;
} DevInfoData;

#define UDID_SHORT_HASH_HEX_STR 16
#define UDID_SHORT_HASH_LEN_TEMP 8
/* DeviceInfo-common */
#define CODE "CODE"
/* VerifyDevice */
#define CODE_VERIFY_DEVICE 2
#define DEVICE_ID "DEVICE_ID"

/* TcpKeepalive */
#define TIME "TIME"
#define CODE_TCP_KEEPALIVE 3

#ifdef __cplusplus
#if __cplusplus
}
#endif
#endif
#endif /* AUTH_MESSAGE_STRUCT_H */