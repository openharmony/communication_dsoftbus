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
#ifndef WIFI_DIRECT_PROTOCOL_H
#define WIFI_DIRECT_PROTOCOL_H

#include "wifi_direct_types.h"
#include "data/info_container.h"

#ifdef __cplusplus
extern "C" {
#endif

#define TLV_TAG_SIZE 1
#define TLV_LENGTH_SIZE1 1
#define TLV_LENGTH_SIZE2 2

enum WifiDirectProtocolType {
    WIFI_DIRECT_PROTOCOL_JSON = 0,
    WIFI_DIRECT_PROTOCOL_TLV = 1,

    WIFI_DIRECT_PROTOCOL_MAX,
};

struct ProtocolFormat {
    uint32_t tagSize;
    uint32_t lengthSize;
};

struct InfoContainer;
#define WIFI_DIRECT_PROTOCOL_BASE                                                                                     \
    enum WifiDirectProtocolType (*getType)(void);                                                                     \
    bool (*pack)(struct WifiDirectProtocol *base, struct InfoContainer *container,                                    \
                 uint8_t **outBuffer, size_t *outSize);                                                               \
    bool (*setDataSource)(struct WifiDirectProtocol *self, const uint8_t *data, size_t size);                         \
    void (*setFormat)(struct WifiDirectProtocol *self, struct ProtocolFormat *format);                                \
    bool (*unpack)(struct WifiDirectProtocol *base, struct InfoContainer *container);                                 \
                                                                                                                      \
    /* for tlv protocol */                                                                                            \
    bool (*writeData)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,                  \
                      uint8_t *data, size_t size);                                                                    \
    bool (*readData)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty,                   \
                     uint8_t **data, size_t *size);                                                                   \
                                                                                                                      \
    /* for json protocol */                                                                                           \
    bool (*writeInt)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, int32_t data);    \
    bool (*writeBoolean)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, bool data);   \
    bool (*writeString)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, char *data);   \
                                                                                                                      \
    bool (*readInt)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, int32_t *data);    \
    bool (*readBoolen)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, bool *data);    \
    bool (*readString)(struct WifiDirectProtocol *base, struct InfoContainerKeyProperty *keyProperty, char **data);   \
                                                                                                                      \
    void (*destructor)(struct WifiDirectProtocol *base);                                                              \
    struct ProtocolFormat format

struct WifiDirectProtocol {
    WIFI_DIRECT_PROTOCOL_BASE;
};

#ifdef __cplusplus
}
#endif
#endif