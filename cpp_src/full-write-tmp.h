/* An interface to write() that writes all it is asked to write.

   Copyright (C) 2002-2003, 2009-2020 Free Software Foundation, Inc.

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU General Public License as published by
   the Free Software Foundation; either version 3 of the License, or
   (at your option) any later version.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU General Public License for more details.

   You should have received a copy of the GNU General Public License
   along with this program.  If not, see <https://www.gnu.org/licenses/>.

   Entirely work of PetaGene offered under the above licence.
   This file is internally copied from cpp_src/full-write-tmp.h - make edits there
   */

#include <stddef.h>
#include <sys/types.h>

#ifndef FULL_WRITE_INCLUDED
#define FULL_WRITE_INCLUDED

#ifdef __cplusplus
extern "C" {
#endif

typedef struct FileHandlerBase  {}  FileHandlerBase; /**< Opaque base to petagene/cuno copy job */

/* Write COUNT bytes at BUF to descriptor FD, retrying if interrupted
   or if partial writes occur.  Return the number of bytes successfully
   written, setting errno if that is less than COUNT.  */
extern size_t full_write (int fd, const void *buf, size_t count);
/* Queue the file copy for writing.
   Returns a pointer to a control value that should be allow_job_close() by the caller when it no longer wants the file handles.
*/
extern FileHandlerBase* queue_file(int src_fd, int fd, size_t max_read, const char* src_name, const char* dst_name);
/** At the end of all copy requests, wait for the remaining jobs to complete */
extern void trigger_join(int i);
/** Tests the file handle to see if cuno has intercepted its open() */
extern int file_is_intercepted(int src_fd);
/** returns true if opaque points to a valid job. False if opaque is NULL */
extern int check_job_is_valid(FileHandlerBase*  opaque);

/** returns true if opaque points to a valid job, aand triggers a file close. False if opaque is NULL, and caller should close */
extern int allow_job_close(FileHandlerBase*  opaque);

#ifdef __cplusplus
}
#endif

#endif // FULL_WRITE_INCLUDED
