/*
 * Copyright (C) 2015 Canonical Ltd
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 3 as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 *
 * Based on ubuntu-core-launcher from: lp:ubuntu-core-launcher
 *
 * gcc -o test-seccomp test-seccomp.c -lseccomp
 */
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <fcntl.h>
#include <stdarg.h>
#include <seccomp.h>

void die(const char *msg, ...)
{
   va_list va;
   va_start(va, msg);
   vfprintf(stderr, msg, va);
   va_end(va);

   fprintf(stderr, "\n");
   exit(1);
}

void debug(const char *msg, ...)
{
   va_list va;
   va_start(va, msg);
   fprintf(stderr, "DEBUG: ");
   vfprintf(stderr, msg, va);
   fprintf(stderr, "\n");
   va_end(va);
}

// strip whitespace from the end of the given string (inplace)
size_t trim_right(char *s, size_t slen) {
   while(slen > 0 && isspace(s[slen - 1])) {
      s[--slen] = 0;
   }
   return slen;
}

int seccomp_load_filters(const char *profile_path)
{
   debug("seccomp_load_filters %s", profile_path);
   int rc = 0;
   int syscall_nr = -1;
   scmp_filter_ctx ctx = NULL;
   FILE *f = NULL;
   size_t lineno = 0;

   ctx = seccomp_init(SCMP_ACT_KILL);
   if (ctx == NULL)
      return ENOMEM;

   f = fopen(profile_path, "r");
   if (f == NULL) {
      fprintf(stderr, "Can not open %s (%s)\n", profile_path, strerror(errno));
      return -1;
   }
   // 80 characters + '\n' + '\0'
   char buf[82];
   while (fgets(buf, sizeof(buf), f) != NULL)
   {
      size_t len;

      lineno++;

      // comment, ignore
      if(buf[0] == '#')
         continue;

      // ensure the entire line was read
      len = strlen(buf);
      if (len == 0)
         continue;
      else if (buf[len - 1] != '\n' && len > (sizeof(buf) - 2)) {
         fprintf(stderr, "seccomp filter line %zu was too long (%zu characters max)\n", lineno, sizeof(buf) - 2);
         rc = -1;
         goto out;
      }

      // kill final newline
      len = trim_right(buf, len);
      if (len == 0)
         continue;

      // check for special "@unrestricted" command
      if (strncmp(buf, "@unrestricted", sizeof(buf)) == 0)
         goto out;

      // syscall not available on this arch/kernel
      // as this is a syscall whitelist its ok and the error can be ignored
      syscall_nr = seccomp_syscall_resolve_name(buf);
      if (syscall_nr == __NR_SCMP_ERROR)
         continue;

      // a normal line with a syscall
      rc = seccomp_rule_add_exact(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
      if (rc != 0) {
         rc = seccomp_rule_add(ctx, SCMP_ACT_ALLOW, syscall_nr, 0);
	 if (rc != 0) {
             fprintf(stderr, "seccomp_rule_add failed with %i for '%s'\n", rc, buf);
             goto out;
	 }
      }
   }

   // load it into the kernel
   rc = seccomp_load(ctx);
   if (rc != 0) {
      fprintf(stderr, "seccomp_load failed with %i\n", rc);
      goto out;
   }

 out:
   if (f != NULL) {
      fclose(f);
   }
   seccomp_release(ctx);
   return rc;
}

int main(int argc, char **argv)
{
    int rc;
    const int NR_ARGS = 1;
    if(argc < NR_ARGS+1)
        die("Usage: %s <filter file> <binary>", argv[0]);

    const char *filter = argv[1];
    const char *binary = argv[2];

    // set seccomp
    rc = seccomp_load_filters(filter);
    if (rc != 0)
        die("seccomp_load_filters failed with %i\n", rc);

    // and exec the new binary
    argv[NR_ARGS] = (char*)binary,
    execv(binary, (char *const*)&argv[NR_ARGS+1]);
    perror("execv failed");
    return 1;
}
