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

#ifndef LNN_MAP_H
#define LNN_MAP_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

/**
 * LNN map node struct
 */
typedef struct tagMapNode {
    uint32_t hash;
    uint32_t valueSize;
    void *key;
    void *value;
    struct tagMapNode *next;
} MapNode;

/**
 * LNN map struct define.
 */
typedef struct {
    MapNode **nodes; /* Map node bucket */
    uint32_t nodeSize; /* Map node count */
    uint32_t bucketSize; /* Map node bucket size */
} Map;

/**
 * LNN map node struct
 */
typedef struct {
    MapNode *node; /* Map node */
    uint32_t nodeNum; /* Map node  */
    uint32_t bucketNum; /* Map node */
    Map *map;
} MapIterator;

MapIterator *LnnMapInitIterator(Map *map);
bool LnnMapHasNext(MapIterator *it);
MapIterator *LnnMapNext(MapIterator *it);
void LnnMapDeinitIterator(MapIterator *it);

/**
 * Initialize map
 *
 * @param : map Map see details in type Map
 */
void LnnMapInit(Map *map);

/**
 * Delete map, free the map memory
 *
 * @param : map Map see details in type Map
 */
void LnnMapDelete(Map *map);

/**
 * Add map element
 *
 * @param : map Map see details in type Map
 *          key Map key
 *          value Map value
 *          valueSize Map value size
 * @return : SOFTBUS_OK or other error
 */
int32_t LnnMapSet(Map *map, const char *key, const void *value, uint32_t valueSize);

/**
 * Get map value
 *
 * @param : map Map see details in type Map
 *          key Map key
 * @return : Value of key or NULL
 */
void *LnnMapGet(const Map *map, const char *key);

/**
 * Erase map element
 * Erase cannot be used on the iterator
 *
 * @param : map Map see details in type Map
 *          key Map key
 */
int32_t LnnMapErase(Map *map, const char *key);

/**
 * get map size
 *
 * @param : map Map see details in type Map
 */
uint32_t MapGetSize(Map *map);

#ifdef __cplusplus
}
#endif /* __cplusplus */

#endif /* LNN_MAP_H */