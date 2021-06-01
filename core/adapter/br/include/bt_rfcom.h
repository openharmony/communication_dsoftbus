/*
 * Copyright (c) 2021 Huawei Device Co., Ltd.
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

#ifndef BT_RFCOM_H
#define BT_RFCOM_H

#include "ohos_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#define BT_ADDR_LEN 6
#define BT_UUID_LEN 16
#define BT_RFCOM_NAME_MAX_LEN 31
#define BT_RFCOM_CLIENT_INVALID_HANDLE 0xFF

typedef uint8 BT_UUID[BT_UUID_LEN];
typedef uint8 BD_ADDR[BT_ADDR_LEN];

typedef enum {
    BT_RFCOM_EVENT_READ = 0x00, /* not used */
    BT_RFCOM_EVENT_ACCEPT,
    BT_RFCOM_EVENT_DISCONNECT,
    BT_RFCOM_EVENT_CONNECT,
    BT_RFCOM_EVENT_CONGEST,
} BtRfcomEventType;

typedef struct {
  /* event type BtRfcomEventType */
    void (*OnEvent)(uint8 type, uint8 handle, int value);
    void (*OnDataReceived)(uint8 handle, const uint8 *buf, uint16 len);
} BtRfcomEventCallback;

typedef enum {
    BT_RFCOM_STATUS_OK,
    BT_RFCOM_STATUS_INVALID_HANDLE,
    BT_RFCOM_STATUS_UNUSED_HANDLE,
    BT_RFCOM_STATUS_INVALID_PARAM,
} BtRfcomStatus;

/*
 * return handle, BT_RFCOM_CLIENT_INVALID_HANDLE is invalid
 */
uint8 BtRfcomClientCreate(const BD_ADDR mac, const BT_UUID uuid);
/*
 * BT_RFCOM_STATUS_OK means success, otherwise fail
 */
uint8 BtRfcomClientConnect(uint8 handle, BtRfcomEventCallback *cb);
/*
 * BT_RFCOM_STATUS_OK means success, otherwise fail
 */
uint8 BtRfcomClientDisconnect(uint8 handle);
/*
 * BT_RFCOM_STATUS_OK means success, otherwise fail
 */
uint8 BtRfcomClientWrite(uint8 handle, uint8 *data, uint16 dataLen);
/*
 * BT_RFCOM_STATUS_OK means success, otherwise fail
 */
uint8 BtRfcomServerAccept(uint8 handle, BtRfcomEventCallback *cb);
/*
 * return handle, BT_RFCOM_CLIENT_INVALID_HANDLE is invalid
 */
uint8 BtRfcomServerCreate(const char *name, const BT_UUID uuid);

void BtRfcomHandleResponse(const uint8 *data, uint16 dataLen);

#ifdef __cplusplus
}
#endif
#endif /* BT_RFCOM_H */
