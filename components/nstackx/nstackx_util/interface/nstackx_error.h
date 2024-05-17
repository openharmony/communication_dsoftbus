/*
 * Copyright (C) 2021 Huawei Device Co., Ltd.
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

#ifndef NSTACKX_ERROR_H
#define NSTACKX_ERROR_H

#ifdef __cplusplus
extern "C" {
#endif

#define NSTACKX_EOK 0 /* OK */
#define NSTACKX_EFAILED (-1) /* Operation failed */

/*
 * Description:Invalid argument.
 * Solution: Verify that related input parameters are correctly set.
 */
#define NSTACKX_EINVAL (-2)
#define NSTACKX_EINPROGRESS (-3) /* Operation now in progress */

/*
 * Description: Device or resource busy.
 * Solution: Please retry later.
 */
#define NSTACKX_EBUSY (-4)

/*
 * Description: Out of memory.
 * Solution: 1. Verify whether the memory has exceeded the threshold.
 *           2. Release the memory and try again.
 */
#define NSTACKX_ENOMEM (-5)
#define NSTACKX_EEXIST (-6) /* Resource already exist */

/*
 * Description: The resource is temporarily unavailable.
 * Solution: Try again later.
 */
#define NSTACKX_EAGAIN (-7)

/*
 * Description: Timeout.
 * Solution: Try again.
 */
#define NSTACKX_ETIMEOUT (-8)

/*
 * Description: Overflow.
 * Solution: Try again.
 */
#define NSTACKX_OVERFLOW (-9)

/*
 * Description: Not exist.
 * Solution: Try again.
 */
#define NSTACKX_NOEXIST (-10)

/*
 * Description: Interrupted system call.
 * Solution: Try again.
 */
#define NSTACKX_EINTR (-11)

#define NSTACKX_TRUE 1
#define NSTACKX_FALSE 0

#define NSTACKX_NOTSUPPORT (-12)

#define NSTACKX_PEER_CLOSE (-13)

#define NSTACKX_EPERM (-14)

#define NSTACKX_EDQUOT (-15)

#define NSTACKX_ENETDOWN (-16)

#define NSTACKX_ENOENT (-17)
#ifdef __cplusplus
}
#endif

#endif // NSTACKX_ERROR_H
