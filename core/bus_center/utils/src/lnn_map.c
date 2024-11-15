/*
 * Copyright (c) 2021-2024 Huawei Device Co., Ltd.
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

#include "lnn_map.h"

#include <stdlib.h>
#include <string.h>

#include <securec.h>

#include "lnn_log.h"
#include "softbus_adapter_mem.h"
#include "softbus_def.h"
#include "softbus_error_code.h"

#define HDF_MIN_MAP_SIZE 8
#define HDF_ENLARGE_FACTOR 2
#define HDF_MAP_KEY_MAX_SIZE 1000
#define HDF_MAP_VALUE_MAX_SIZE 4000
#define SHIFT_ALIGN_BYTE 4

/* BKDR Hash */
static uint32_t MapHash(const char *key)
{
    uint32_t hash = 0;
    const uint32_t seed = 131;
    if (key == NULL) {
        return 0;
    }
    uint32_t len = strlen(key);
    for (uint32_t i = 0; i < len; i++) {
        hash = (hash * seed) + (*key++);
    }

    return (hash & 0x7FFFFFFF);
}

static int32_t MapHashIdx(const Map *map, uint32_t hash)
{
    if (map->bucketSize < 1) {
        return -1;
    }
    return (int32_t)(hash & (map->bucketSize - 1));
}

static void MapAddNode(Map *map, MapNode *node)
{
    int32_t idx = MapHashIdx(map, node->hash);
    if (idx < 0) {
        LNN_LOGE(LNN_STATE, "invalid param, get map hash idx failed");
        return;
    }
    node->next = map->nodes[idx];
    map->nodes[idx] = node;
}

static int32_t MapResize(Map *map, uint32_t size)
{
    uint32_t bucketSize;
    MapNode **nodes = NULL;
    MapNode **tmp = NULL;

    nodes = (MapNode **)SoftBusCalloc(size * sizeof(*nodes));
    if (nodes == NULL) {
        LNN_LOGE(LNN_STATE, "calloc node fail");
        return SOFTBUS_MEM_ERR;
    }

    tmp = map->nodes;
    bucketSize = map->bucketSize;
    map->nodes = nodes;
    map->bucketSize = size;

    if (tmp != NULL) {
        MapNode *node = NULL;
        MapNode *next = NULL;

        /* remap node with new map size */
        for (uint32_t i = 0; i < bucketSize; i++) {
            node = tmp[i];
            while (node != NULL) {
                next = node->next;
                MapAddNode(map, node);
                node = next;
            }
        }
        SoftBusFree(tmp);
    }
    return SOFTBUS_OK;
}

static MapNode *MapCreateNode(const char *key, uint32_t hash,
    const void *value, uint32_t valueSize)
{
    uint32_t keySize = strlen(key) + 1;
    keySize = keySize + (SHIFT_ALIGN_BYTE - keySize % SHIFT_ALIGN_BYTE);
    MapNode *node = (MapNode *)SoftBusCalloc(sizeof(*node) + keySize + valueSize);
    if (node == NULL) {
        LNN_LOGE(LNN_STATE, "calloc node fail");
        return NULL;
    }

    node->hash = hash;
    node->key = (uint8_t *)node + sizeof(*node);
    node->value = (uint8_t *)node + sizeof(*node) + keySize;
    node->valueSize = valueSize;
    if (memcpy_s(node->key, keySize, key, strlen(key) + 1) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy node key fail");
        SoftBusFree(node);
        return NULL;
    }
    if (memcpy_s(node->value, node->valueSize, value, valueSize) != EOK) {
        LNN_LOGE(LNN_STATE, "memcpy node value fail");
        SoftBusFree(node);
        return NULL;
    }
    return node;
}

/**
 * Add map element
 *
 * @param : map Map see details in type Map
 *          key Map key
 *          value Map value
 *          valueSize Map value size
 * @return : SOFTBUS_OK or other error
 */
int32_t LnnMapSet(Map *map, const char *key, const void *value, uint32_t valueSize)
{
    MapNode *node = NULL;

    bool isParamsInvalid = (map == NULL || key == NULL || value == NULL || valueSize == 0);
    if (isParamsInvalid) {
        return SOFTBUS_INVALID_PARAM;
    }
    if (valueSize > HDF_MAP_VALUE_MAX_SIZE || strlen(key) > HDF_MAP_KEY_MAX_SIZE) {
        return SOFTBUS_INVALID_PARAM;
    }
    uint32_t hash = MapHash(key);
    if (map->nodeSize > 0 && map->nodes != NULL) {
        int32_t idx = MapHashIdx(map, hash);
        if (idx < 0) {
            LNN_LOGE(LNN_STATE, "invalid param, get map hash idx failed");
            return SOFTBUS_INVALID_PARAM;
        }
        node = map->nodes[idx];
        while (node != NULL) {
            if (node->hash != hash || node->key == NULL || strcmp(node->key, key) != 0) {
                node = node->next;
                continue;
            }

            // size unmatch
            if (node->value == NULL || node->valueSize != valueSize) {
                return SOFTBUS_INVALID_PARAM;
            }
            // update k-v node
            if (memcpy_s(node->value, node->valueSize, value, valueSize) != EOK) {
                return SOFTBUS_MEM_ERR;
            }

            return SOFTBUS_OK;
        }
    }
    // for decreasing map search conflict, enlarge bucket Size
    if (map->nodeSize >= map->bucketSize) {
        uint32_t size = (map->bucketSize < HDF_MIN_MAP_SIZE) ? HDF_MIN_MAP_SIZE : \
            (map->bucketSize << HDF_ENLARGE_FACTOR);
        MapResize(map, size);
    }

    if (map->nodes == NULL) {
        LNN_LOGE(LNN_STATE, "map node is null");
        return SOFTBUS_INVALID_PARAM;
    }
    node = MapCreateNode(key, hash, value, valueSize);
    if (node == NULL) {
        LNN_LOGE(LNN_STATE, "create node fail");
        return SOFTBUS_INVALID_PARAM;
    }
    MapAddNode(map, node);
    map->nodeSize++;

    return SOFTBUS_OK;
}

/**
 * Get map value api
 *
 * @param : map Map see details in type Map
 *          key Map key
 * @return : value of key or NULL
 */
void* LnnMapGet(const Map *map, const char *key)
{
    if (map == NULL || key == NULL || map->nodeSize == 0 || map->nodes == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return NULL;
    }

    uint32_t hash = MapHash(key);
    int32_t idx = MapHashIdx(map, hash);
    if (idx < 0) {
        LNN_LOGE(LNN_STATE, "invalid param, get map hash idx failed");
        return NULL;
    }
    MapNode *node = map->nodes[idx];

    while (node != NULL) {
        if (node->hash == hash && node->key != NULL && !strcmp(node->key, key)) {
            return node->value;
        }

        node = node->next;
    }

    return NULL;
}

/**
 * Erase map node
 *
 * @param : map Map see details in type Map
 *          key Map key
 */
int32_t LnnMapErase(Map *map, const char *key)
{
    if (map == NULL || key == NULL || map->nodeSize == 0 || map->nodes == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return SOFTBUS_INVALID_PARAM;
    }

    uint32_t hash = MapHash(key);
    int32_t idx = MapHashIdx(map, hash);
    if (idx < 0) {
        LNN_LOGE(LNN_STATE, "invalid param, get map hash idx failed");
        return SOFTBUS_INVALID_PARAM;
    }
    MapNode *node = map->nodes[idx];
    MapNode *prev = node;

    while (node != NULL) {
        if (node->hash == hash && node->key != NULL && !strcmp(node->key, key)) {
            if (map->nodes[idx] == node) {
                map->nodes[idx] = node->next;
            } else {
                prev->next = node->next;
            }
            SoftBusFree(node);
            map->nodeSize--;
            return SOFTBUS_OK;
        }
        prev = node;
        node = node->next;
    }

    return SOFTBUS_INVALID_PARAM;
}

/**
 * get map size
 *
 * @param : map Map see details in type Map
 */
uint32_t MapGetSize(Map *map)
{
    return (map == NULL) ? 0 : map->nodeSize;
}

/**
 * initialize map
 *
 * @param : map Map see details in type Map
 */
void LnnMapInit(Map *map)
{
    if (map == NULL) {
        return;
    }

    map->nodes = NULL;
    map->nodeSize = 0;
    map->bucketSize = 0;
}

/**
 * delete map, free the map memory
 *
 * @param : map Map see details in type Map
 */
void LnnMapDelete(Map *map)
{
    uint32_t i;
    MapNode *node = NULL;
    MapNode *next = NULL;

    if (map == NULL || map->nodes == NULL) {
        LNN_LOGE(LNN_STATE, "invalid param");
        return;
    }

    for (i = 0; i < map->bucketSize; i++) {
        node = map->nodes[i];
        while (node != NULL) {
            next = node->next;
            SoftBusFree(node);
            node = next;
        }
    }

    SoftBusFree(map->nodes);

    map->nodes = NULL;
    map->nodeSize = 0;
    map->bucketSize = 0;
}

/**
 * init LNN map iterator
 *
 * @param : map Map see details in type Map
 */
MapIterator *LnnMapInitIterator(Map *map)
{
    MapIterator *it = NULL;
    if (map == NULL) {
        LNN_LOGE(LNN_STATE, "map is null");
        return NULL;
    }
    it = (MapIterator *)SoftBusCalloc(sizeof(MapIterator));
    if (it == NULL) {
        LNN_LOGE(LNN_STATE, "calloc iterator fail");
        return NULL;
    }
    it->node = NULL;
    it->bucketNum = 0;
    it->nodeNum = 0;
    it->map = map;
    return it;
}

/**
 * Have a  next element
 *
 * @param : it Iterator see details in type Iterator
 */
bool LnnMapHasNext(MapIterator *it)
{
    if (it->map->nodeSize > HDF_MAP_KEY_MAX_SIZE) {
        LNN_LOGW(LNN_STATE, "nodeSize=%{public}d", it->map->nodeSize);
    }
    return (it->nodeNum < it->map->nodeSize);
}

/**
 * Get next iterator API
 *
 * @param : it Iterator see details in type Iterator
 */
MapIterator *LnnMapNext(MapIterator *it)
{
    MapNode *node = NULL;
    if (it == NULL) {
        return NULL;
    }
    if (LnnMapHasNext(it)) {
        if (it->node != NULL && it->node->next != NULL) {
            it->nodeNum++;
            it->node = it->node->next;
            return it;
        }
        while (it->bucketNum < it->map->bucketSize) {
            node = it->map->nodes[it->bucketNum];
            it->bucketNum++;
            if (node != NULL) {
                it->nodeNum++;
                it->node = node;
                return it;
            }
        }
    }
    return it;
}

/**
 * deinit iterator and free memory API
 *
 * @param : it Iterator see details in type Iterator
 */
void LnnMapDeinitIterator(MapIterator *it)
{
    if (it == NULL) {
        return;
    }
    SoftBusFree(it);
}