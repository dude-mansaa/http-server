/*
 * Copyright (c) 2014-2018 Cesanta Software Limited
 * All rights reserved
 *
 * Licensed under the Apache License, Version 2.0 (the ""License"");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an ""AS IS"" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include "mgos_http_server.h"

#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "common/cs_dbg.h"
#include "common/cs_file.h"
#include "common/json_utils.h"
#include "common/str_util.h"

#if defined(MGOS_HAVE_ATCA)
#include "mgos_atca.h"
#endif
#include "mgos_config_util.h"
#include "mgos_debug.h"
#include "mgos_debug_hal.h"
#include "mgos_hal.h"
#include "mgos_init.h"
#include "mgos_mongoose.h"
#include "mgos_net.h"
#include "mgos_sys_config.h"
#include "mgos_updater_common.h"
#include "mgos_utils.h"

#define MGOS_F_RELOAD_CONFIG MG_F_USER_5


static struct mg_connection *s_listen_conn;
static struct mg_connection *s_listen_conn_tun;
static struct mg_serve_http_opts s_http_server_opts;
#define JSON_HEADERS "Connection: close\r\nContent-Type: application/json"


static void ev_handler(struct mg_connection *nc, int ev, void *p,void *user_data) {
  LOG(LL_DEBUG, ("HTTP Server got request"));
  if (ev == MG_EV_HTTP_REQUEST) {
    mg_serve_http(nc, (struct http_message *) p, s_http_server_opts);
  }
}

bool mgos_http_server_init(void) {
  if (!mgos_sys_config_get_http_enable()) {
    return true;
  }

  if (mgos_sys_config_get_http_listen_addr() == NULL) {
    LOG(LL_WARN, ("HTTP Server disabled, listening address is empty"));
    return true; /* At this moment it is just warning */
  }
  struct mg_bind_opts opts;
  memset(&opts, 0, sizeof(opts));
  s_listen_conn =
      mg_bind_opt(mgos_get_mgr(), mgos_sys_config_get_http_listen_addr(),
                  ev_handler, NULL, opts);
  if (!s_listen_conn) {
    LOG(LL_ERROR,
        ("Error binding to [%s]", mgos_sys_config_get_http_listen_addr()));
    return false;
  }
  s_listen_conn->recv_mbuf_limit = MGOS_RECV_MBUF_LIMIT;
  mg_set_protocol_http_websocket(s_listen_conn);
  LOG(LL_INFO,
      ("Light server started on [%s]", mgos_sys_config_get_http_listen_addr()));
  s_http_server_opts.document_root="/";
  s_http_server_opts.enable_directory_listing="yes";
  mg_register_http_endpoint_opt(s_listen_conn,"/api",ev_handler,s_http_server_opts);
  mgos_register_http_endpoint("/api",ev_handler,NULL);
  
  return true;
}

void mgos_register_http_endpoint_opt(const char *uri_path,
                                     mg_event_handler_t handler,
                                     struct mg_http_endpoint_opts opts) {
  if (s_listen_conn != NULL) {
    mg_register_http_endpoint_opt(s_listen_conn, uri_path, handler, opts);
  }
  if (s_listen_conn_tun != NULL) {
    mg_register_http_endpoint_opt(s_listen_conn_tun, uri_path, handler, opts);
  }
}

void mgos_register_http_endpoint(const char *uri_path,
                                 mg_event_handler_t handler, void *user_data) {
  struct mg_http_endpoint_opts opts;
  memset(&opts, 0, sizeof(opts));
  opts.user_data = user_data;
  opts.auth_domain = mgos_sys_config_get_http_auth_domain();
  opts.auth_file = mgos_sys_config_get_http_auth_file();
  mgos_register_http_endpoint_opt(uri_path, handler, opts);
}

struct mg_connection *mgos_get_sys_http_server(void) {
  return s_listen_conn;
}

void mgos_http_server_set_document_root(const char *document_root) {
  s_http_server_opts.document_root = document_root;
}
