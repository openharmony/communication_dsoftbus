/*
 * Copyright (c) 2023-2024 Huawei Device Co., Ltd.
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

#ifndef DISC_COAP_PARSER_H
#define DISC_COAP_PARSER_H

#include "softbus_common.h"
#include "softbus_json_utils.h"
#include "disc_manager.h"

#define SERVICE_DATA_PORT "port"
#define DEVICE_UDID       "UDID"
#define JSON_SERVICE_DATA "serviceData"

#define MAX_PORT_STR_LEN  6
#define MAX_SERVICE_DATA_LEN 64

#ifdef __cplusplus
extern "C" {
#endif

int32_t DiscCoapParseDeviceUdid(const char *raw, DeviceInfo *device);
void DiscCoapParseWifiIpAddr(const cJSON *data, DeviceInfo *device);
int32_t DiscCoapParseServiceData(const cJSON *data, DeviceInfo *device);
void DiscCoapParseHwAccountHash(const cJSON *data, DeviceInfo *device);
int32_t DiscCoapFillServiceData(const PublishOption *option, char *outData, uint32_t outDataLen, uint32_t allCap);
int32_t DiscCoapParseKeyValueStr(const char *src, const char *key, char *outValue, uint32_t outLen);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif