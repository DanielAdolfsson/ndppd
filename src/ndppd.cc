// ndppd - NDP Proxy Daemon
// Copyright (C) 2011  Daniel Adolfsson <daniel.adolfsson@tuhox.com>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.
#include <iostream>
#include <string>

#include <getopt.h>
#include <sys/time.h>

#include <sys/types.h>
#include <unistd.h>

#include "ndppd.h"

using namespace ndppd;

int daemonize()
{
   pid_t pid = fork();

   if(pid < 0)
      return -1;

   if(pid > 0)
      exit(0);

   pid_t sid = setsid();

   if(sid < 0)
      return -1;

   close(STDIN_FILENO);
   close(STDOUT_FILENO);
   close(STDERR_FILENO);

   return 0;
}

int main(int argc, char *argv[], char *env[])
{
//   std::string config_path("/etc/ndppd.conf");
   std::string config_path("../ndppd.conf");
   bool daemon = false;

   while(1)
   {
      int c, opt;

      static struct option long_options[] =
      {
         { "config", 1, 0, 'c' },
         { "daemon", 0, 0, 'd' },
         { 0, 0, 0, 0}
      };

      c = getopt_long(argc, argv, "c:d", long_options, &opt);

      if(c == -1)
         break;

      switch(c)
      {
      case 'c':
         if(!optarg)
         {
            ERR("Invalid arguments");
            return -1;
         }

         config_path = optarg;
         break;

      case 'd':
         daemon = true;
         break;
      }
   }

   if(daemon)
   {
      log::syslog(true);

      if(daemonize() < 0)
      {
         ERR("Failed to daemonize process");
         return 1;
      }
   }

   NFO("Using configuration file '%s'", config_path.c_str());

   if(!conf::load(config_path))
      return -1;

   struct timeval t1, t2;

   gettimeofday(&t1, 0);

   while(iface::poll_all() >= 0)
   {
      int elapsed_time;
      gettimeofday(&t2, 0);

      elapsed_time =
         ((t2.tv_sec  - t1.tv_sec)  * 1000) +
         ((t2.tv_usec - t1.tv_usec) / 1000);

      t1.tv_sec  = t2.tv_sec;
      t1.tv_usec = t2.tv_usec;

      session::update_all(elapsed_time);
   }

   ERR("iface::poll_all() failed");

   return 0;
}

