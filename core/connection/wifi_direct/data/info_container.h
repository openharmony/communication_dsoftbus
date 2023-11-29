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
#ifndef WIFI_DIRECT_INFO_CONTAINER_H
#define WIFI_DIRECT_INFO_CONTAINER_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "softbus_adapter_mem.h"
#include "wifi_direct_defines.h"
#include "wifi_direct_types.h"

#ifdef __cplusplus
extern "C" {
#endif

enum InfoContainerEntryType {
    STRING = 1,
    STRING_ARRAY = 2,
    INT = 3,
    INT_ARRAY = 4,
    BYTE = 5,
    BYTE_ARRAY = 6,
    BOOLEAN = 7,
    INTERFACE_INFO_ARRAY = 8,
    LONG = 9,
    LINK_INFO = 10,
    IPV4_INFO = 11,
    IPV4_INFO_ARRAY = 12,
    AUTH_CONNECTION = 13,
    EXTRA_DATA_ARRAY = 14,
    INNER_LINK = 15,
    COEXIST_SET = 16,
};

#define CONTAINER_FLAG (1 << 0)
#define CONTAINER_ARRAY_FLAG (1 << 1)
#define MAC_ADDR_FLAG (1 << 2)
#define IP_ADDR_FLAG (1 << 2)
#define DEVICE_ID_FLAG (1 << 3)
#define DUMP_FLAG (1 << 4)

struct InfoContainerKeyProperty {
    uint32_t tag;
    char *content;
    enum InfoContainerEntryType type;
    uint32_t flag;
};

struct WifiDirectProtocol;

#define IC_KEY_PROPERTY(key, tag, content, type, flag)                                              \
    [key] = { tag, content, type, flag }

#define IC_DECLARE_KEY_PROPERTIES(type, max)                                                        \
static struct InfoContainerKeyProperty type##KeyProperties[max]

#define INFO_CONTAINER_BASE(type, max)                                                              \
    void (*deepCopy)(struct type *self, struct type *other);                                        \
    void (*putInt)(struct type *self, size_t key, int32_t value);                                   \
    void (*putBoolean)(struct type *self, size_t key, bool value);                                  \
    void (*putPointer)(struct type *self, size_t key, void **ptr);                                  \
    void (*putString)(struct type *self, size_t key, const char *value);                            \
    void (*putIntArray)(struct type *self, size_t key, int32_t *array, size_t arraySize);           \
    void (*putRawData)(struct type *self, size_t key, void *value, size_t size);                    \
    void (*putContainer)(struct type *self, size_t key, struct InfoContainer *container,            \
                            size_t size);                                                           \
    void (*putContainerArray)(struct type *self, size_t key, struct InfoContainer *containerArray,  \
                              size_t containerArraySize, size_t containerSize);                     \
                                                                                                    \
    void* (*get)(struct type *self, size_t key, size_t *size, size_t *count);                       \
    int32_t (*getInt)(struct type *self, size_t key, int32_t defaultValue);                         \
    bool (*getBoolean)(struct type *self, size_t key, bool defaultValue);                           \
    void* (*getPointer)(struct type *self, size_t key, void *defaultValue);                         \
    char* (*getString)(struct type *self, size_t key, const char *defaultValue);                    \
    int32_t* (*getIntArray)(struct type *self, size_t key, size_t *arraySize, void *defaultValue);  \
    void* (*getContainer)(struct type *self, size_t key);                                           \
    void* (*getContainerArray)(struct type *self, size_t key, size_t *containerArraySize);          \
    void* (*getRawData)(struct type *self, size_t key, size_t *size, void *defaultValue);           \
                                                                                                    \
    /* debug */                                                                                     \
    void (*dump)(struct type *self, int32_t fd);                                                    \
                                                                                                    \
    bool (*isEmpty)(struct type *self);                                                             \
    void (*remove)(struct type *self, size_t key);                                                  \
    struct InfoContainerKeyProperty* (*getKeyProperty)(struct type *self, uint32_t key);            \
                                                                                                    \
    /* virtual method */                                                                            \
    size_t (*getKeySize)(void);                                                                     \
    const char* (*getContainerName)(void );                                                         \
    bool (*marshalling)(struct type *self, struct WifiDirectProtocol *protocol);                    \
    bool (*unmarshalling)(struct type *self, struct WifiDirectProtocol *protocol);                  \
    void (*destructor)(struct type *self);                                                          \
                                                                                                    \
    /* data member */                                                                               \
    bool dumpFilter;                                                                                \
    struct InfoContainerKeyProperty *keyProperties;                                                 \
    struct {                                                                                        \
        void *data;                                                                                 \
        size_t count;                                                                               \
        size_t size;                                                                                \
        bool remove;                                                                                \
    } entries[max];

struct InfoContainer {
    INFO_CONTAINER_BASE(InfoContainer, 0);
};

void InfoContainerConstructor(struct InfoContainer *self, struct InfoContainerKeyProperty *keyProperties, size_t max);
void InfoContainerDestructor(struct InfoContainer *self, size_t max);

#ifdef __cplusplus
}
#endif
#endif