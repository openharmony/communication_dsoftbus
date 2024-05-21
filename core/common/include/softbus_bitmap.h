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
#ifndef SOFTBUS_BITMAP_H
#define SOFTBUS_BITMAP_H

#include <stdbool.h>
#include <stdint.h>

#ifdef __cplusplus
#if __cplusplus
extern "C" {
#endif
#endif


#define DATA_ONE(y) (1 + ((y) - (y)))
#define SOFTBUS_BIT(n) (1U << (n))
#define SOFTBUS_BITGET(x, bit) ((x) & (DATA_ONE(x) << (bit)))
#define SOFTBUS_BITSHIFT (x, bit) (((x) >> (bit)) & 1)
#define SOFTBUS_BITSGET(x, high, low) ((x) & (((DATA_ONE(x) << ((high) + 1)) - 1) & ~((DATA_ONE(x) << (low)) - 1)))
#define SOFTBUS_BITSSHIFT(x, high, low) (((x) >> (low)) & ((DATA_ONE(x) << ((high) - (low) + 1)) - 1))
#define SOFTBUS_BITISSET (x, bit) (((x) & (DATA_ONE(x) << (bit))) ? 1 : 0)

void SoftbusBitmapSet(uint32_t *bitmap, const uint8_t pos);
void SoftbusBitmapClr(uint32_t *bitmap, const uint8_t pos);
bool SoftbusIsBitmapSet(const uint32_t *bitMap, const uint8_t pos);

#ifdef __cplusplus
#if __cplusplus
}
#endif /* __cplusplus */
#endif /* __cplusplus */
#endif /* SOFTBUS_BITMAP_H */