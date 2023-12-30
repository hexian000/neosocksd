/* csnippets (c) 2019-2024 He Xian <hexian000@outlook.com>
 * This code is licensed under MIT license (see LICENSE for details) */

#ifndef IO_FILE_H
#define IO_FILE_H

#include "stream.h"

#include <stdio.h>

/**
 * @defgroup file
 * @brief Streaming wrapper for FILE *.
 * @{
 */

/**
 * @brief Create reader from a file object.
 * @param[in] f Transfer ownership of the file object.
 * @return If malloc failed or f == NULL, returns NULL.
 * @details The stream is unbuffered.
 */
struct stream *io_filereader(FILE *f);

/**
 * @brief Create writer from a file object.
 * @param[in] f Transfer ownership of the file object.
 * @return If malloc failed or f == NULL, returns NULL.
 * @details The stream is unbuffered.
 */
struct stream *io_filewriter(FILE *f);

/** @} */

#endif /* IO_FILE_H */
