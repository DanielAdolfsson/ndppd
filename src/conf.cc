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
#include <cstdio>
#include <cstdarg>
#include <netinet/ip6.h>
#include <confuse.h>

#include "ndppd.h"

__NDPPD_NS_BEGIN

void conf::error_printf(cfg_t *cfg, const char *fmt, va_list ap)
{
   char buf[256];

   if(vsnprintf(buf, sizeof(buf), fmt, ap) <= 0)
      return;

   ERR("[Config] %s", buf);
}

int conf::validate_rule(cfg_t *cfg, cfg_opt_t *opt)
{
   struct in6_addr addr, mask;

   cfg_t *rule_cfg = cfg_opt_getnsec(opt, cfg_opt_size(opt) - 1);

   if(!rule_cfg)
      return -1;

   // TODO: Maybe we should validate IP here?

   return 0;
}

bool conf::setup(cfg_t *cfg)
{
   int i;

   for(i = 0; i < cfg_size(cfg, "proxy"); i++)
   {
      cfg_t *proxy_cfg = cfg_getnsec(cfg, "proxy", i);

      if(proxy_cfg)
      {
         cfg_t *rule_cfg;
         int i2;

         strong_ptr<proxy> pr = proxy::open(cfg_title(proxy_cfg));

         if(pr.is_null())
            continue;

         pr->router(cfg_getbool(proxy_cfg, "router"));

         for(i2 = 0; i2 < cfg_size(proxy_cfg, "rule"); i2++)
         {
            cfg_t *rule_cfg;

            if(!(rule_cfg = cfg_getnsec(proxy_cfg, "rule", i2)))
               continue;

            address addr(cfg_title(rule_cfg));

            std::string ifname(cfg_getstr(rule_cfg, "iface"));

            if(ifname.empty())
            {
               if(addr.prefix() <= 120)
                  NCE("Static rule prefix /%d <= 120 - is this what you want?", addr.prefix());

               pr->add_rule(addr);
            }
            else
            {
               pr->add_rule(addr, iface::open_ifd(ifname));
            }
         }
      }
   }

   return 0;
}

bool conf::load(const std::string& path)
{
   cfg_t *cfg;
   int i, sz;

   #define _S (char *)

   static cfg_opt_t rule_opts[] =
   {
      CFG_STR  (_S "iface",   _S "",         CFGF_NONE),
      CFG_END  ()
   };

   static cfg_opt_t proxy_opts[] =
   {
      CFG_SEC  (_S "rule",    rule_opts,     CFGF_MULTI | CFGF_TITLE),
      CFG_BOOL (_S "router",  cfg_true,      CFGF_NONE),
      CFG_END  ()
   };

   static cfg_opt_t opts[] =
   {
      CFG_SEC  (_S "proxy",   proxy_opts,    CFGF_MULTI | CFGF_TITLE),
      CFG_FUNC (_S "include", &cfg_include),
      CFG_END()
   };

   cfg = cfg_init(opts, CFGF_NOCASE);

   cfg_set_error_function(cfg, &error_printf);

   cfg_set_validate_func(cfg, "proxy|rule", &validate_rule);

   switch(cfg_parse(cfg, path.c_str()))
   {
      case CFG_SUCCESS:
         break;

      default:
         ERR("Failed to load configuration file '%s'", path.c_str());
         return false;
   }

   setup(cfg);

   cfg_free(cfg);

   return true;
}

__NDPPD_NS_END
