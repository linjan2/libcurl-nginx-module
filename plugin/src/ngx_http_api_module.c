#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

#include <curl/curl.h>


//
// CURL SOCKETS TRIGGERS
// ---------------------
// Keep track of curl's sockets in order to trigger on read/write events.
// Kept in a doubly linked list so that any one of them can be removed more easily.
//
typedef struct api_curl_socket
{
    ngx_connection_t dummy_connection;
    ngx_event_t rev;
    ngx_event_t wev;
    int done;
    struct api_curl_socket *prev;
    struct api_curl_socket *next;
} api_curl_socket_t;

//
// REQUEST CONTEXT DATA
// --------------------
// Stores data for a single client HTTP request.
//
typedef struct ngx_http_api_ctx
{
    ngx_http_request_t *r;
    ngx_str_t content_type;
    int response_status;
    ngx_chain_t *input;
    ngx_chain_t *input_end; // last link in chain
    ngx_chain_t *output;
    ngx_chain_t *output_end; // last link in chain
    CURL *easy_handle;
    api_curl_socket_t *curl_sockets;
    struct curl_slist *httpheader;
    // struct curl_slist *resolve;
    char errorbuffer[CURL_ERROR_SIZE];
} ngx_http_api_ctx_t;

//
// CONFIGURATION DATA
// ------------------
// Stores data from nginx.conf and curl multihandle controls.
//
typedef struct ngx_http_api_main_conf
{
    ngx_array_t *config;
    ngx_log_t *log;
    ngx_event_t timer;
    CURLM *curlm;
} ngx_http_api_main_conf_t;

typedef struct ngx_http_api_loc_conf
{
    ngx_str_t name;
    ngx_str_t url;
} ngx_http_api_loc_conf_t;

static char* ngx_http_api_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr);
static void* ngx_http_api_create_main_conf(ngx_conf_t *cf);
static ngx_int_t ngx_http_api_init_process(ngx_cycle_t *cycle);
static void ngx_http_api_exit_process(ngx_cycle_t *cycle);

static void* ngx_http_api_create_loc_conf(ngx_conf_t *cf);
static char* ngx_http_api_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child);
static char* ngx_http_api_enable(ngx_conf_t *cf, ngx_command_t *cmd, void *location_conf_ptr);
static ngx_int_t ngx_http_api_request_handler(ngx_http_request_t *r);
static void ngx_http_api_request_data_handler(ngx_http_request_t *r);

static ngx_int_t process_request_parameters(ngx_http_request_t *r, ngx_http_api_ctx_t *api_request);
static ngx_int_t send_response(ngx_http_api_ctx_t *api_request);
static ngx_int_t api_request_start(ngx_http_api_ctx_t *api_request);
static void request_cleanup(void *data);



//
// CONFIGURATION CALLBACKS
// -----------------------
// Callbacks for module's directives in nginx.conf.
// Sets the name, the valid locations, and expected arguments.
// 
static ngx_command_t
ngx_http_api_commands[] =
{
    {   // directive to set api_config for main configuration
        ngx_string("api_config"),
        NGX_HTTP_MAIN_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_array_slot,
        NGX_HTTP_MAIN_CONF_OFFSET,
        offsetof(ngx_http_api_main_conf_t, config),
        NULL // post handler
    },
    {   // directive to set HTTP request handler for location
        ngx_string("api_enable"),
        NGX_HTTP_LOC_CONF | NGX_CONF_NOARGS,
        ngx_http_api_enable,
        NGX_HTTP_LOC_CONF_OFFSET,
        0, // not used;
        NULL // post handler
    },
    {   // directive to set name string for location
        ngx_string("api_name"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_api_loc_conf_t, name),
        NULL // post handler
    },
    {   // directive to set url string for location
        ngx_string("api_url"),
        NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
        ngx_conf_set_str_slot,
        NGX_HTTP_LOC_CONF_OFFSET,
        offsetof(ngx_http_api_loc_conf_t, url),
        NULL // post handler
    },
    ngx_null_command
};

//
// MODULE CALLBACKS
// ----------------
// Sets the callbacks for when nginx.conf is processed.
//
static ngx_http_module_t
ngx_http_api_module_ctx =
{
    NULL, // preconfiguration
    NULL, // postconfiguration
    ngx_http_api_create_main_conf, // create main configuration
    ngx_http_api_init_main_conf, // init main configuration
    NULL, // create server configuration
    NULL, // merge server configuration
    ngx_http_api_create_loc_conf, // allocates and initializes location-scope struct
    ngx_http_api_merge_loc_conf   // sets location-scope struct values from outer scope if left unset in location scope
};

//
// MODULE
// ------
// Struct that plugs into nginx modules list.
// No callbacks are used; they would otherwise be called at startup and shutdown of nginx.
//
ngx_module_t
ngx_http_api_module =
{
    NGX_MODULE_V1,
    &ngx_http_api_module_ctx,  // module callbacks
    ngx_http_api_commands,     // module configuration callbacks
    NGX_HTTP_MODULE,           // module type is HTTP
    NULL,        // init_master
    NULL,        // init_module
    ngx_http_api_init_process, // init_process
    NULL,        // init_thread
    NULL,        // exit_thread
    ngx_http_api_exit_process, // exit_process
    NULL,        // exit_master
    NGX_MODULE_V1_PADDING
};

static void*
ngx_http_api_create_main_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "api: %s", __FUNCTION__);
    ngx_http_api_main_conf_t *main_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_main_conf_t));
    if (main_conf != NULL)
    {
        main_conf->config = NGX_CONF_UNSET_PTR;
    }

    return main_conf;
}
static char*
ngx_http_api_init_main_conf(ngx_conf_t *cf, void *main_conf_ptr)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,"%s", __FUNCTION__);
    ngx_http_api_main_conf_t *main_conf = main_conf_ptr;
    if (main_conf->config == NGX_CONF_UNSET_PTR)
    {   // TODO: set default
    }
    return NGX_CONF_OK;
}

static void*
ngx_http_api_create_loc_conf(ngx_conf_t *cf)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "api: %s", __FUNCTION__);
    ngx_http_api_loc_conf_t *location_conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_api_loc_conf_t));
    if (location_conf != NULL)
    {   // initialize as unset if merged with other conf
    }
    return location_conf;
}

static char*
ngx_http_api_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "api: %s", __FUNCTION__);
    ngx_http_api_loc_conf_t *prev = parent;
    ngx_http_api_loc_conf_t *location_conf = child;
    ngx_conf_merge_str_value(location_conf->name, prev->name, /*default*/ "default_name");
    ngx_conf_merge_str_value(location_conf->url, prev->url, /*default*/ "http://localhost:8888/test");
    return NGX_CONF_OK;
}

static char*
ngx_http_api_enable(ngx_conf_t *cf, ngx_command_t *cmd, /*ngx_http_api_loc_conf_t*/ void *location_conf_ptr)
{
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "api: %s", __FUNCTION__);
    ngx_http_core_loc_conf_t *http_loc_conf = ngx_http_conf_get_module_loc_conf(cf, ngx_http_core_module);
    http_loc_conf->handler = ngx_http_api_request_handler; // sets HTTP request handler
    return NGX_CONF_OK;
}

// --------------------------------------------------------------------------

void
empty_handler(ngx_event_t *ev)
{
    ngx_log_error(NGX_LOG_NOTICE, ev->log, 0, "%s, ev->write = %d", __FUNCTION__, ev->write);
}


static size_t
readfunction(char *buffer, size_t size, size_t nitems, void *userdata)
{   // provide data chunk to send
    size_t maxsize = size * nitems;
    ngx_http_api_ctx_t *api_request = userdata;
    ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s", __FUNCTION__);
    
    // copy no more than 'size' * 'nitems' bytes into buffer
    size_t realsize = 0;

    int last_buf = 0;
    ngx_chain_t *cl = api_request->input;
    for (; cl; cl = cl->next)
    {
        size_t buffer_size = ngx_buf_size(cl->buf);
        if (buffer_size > maxsize)
        {
            ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: buffer_size > maxsize; %d > %d", buffer_size, maxsize);
            return CURL_READFUNC_ABORT;
        }
        if (realsize + buffer_size > maxsize)
        {   // can't write more buffers, wait to be called again
            break;
        }
        realsize += buffer_size;
        ngx_memcpy(buffer, cl->buf->pos, buffer_size);
        last_buf = cl->buf->last_buf;
    }

    api_request->input = cl; // remove handled chain links

    if (realsize == 0 && !last_buf)
    {
        // pause until more input is available; up-unpaused by: curl_easy_pause(easy_handle, CURLPAUSE_CONT)
        ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s CURL_READFUNC_PAUSE", __FUNCTION__);
        return CURL_READFUNC_PAUSE;
    }
    return realsize;
    // returning 0 signals end-of-file and stops the current transfer;
    // if less than specified content-length remote server may hang
    // return CURL_READFUNC_ABORT to generate CURLE_ABORTED_BY_CALLBACK from transport
    // return CURL_READFUNC_PAUSE to cause reading from this connection to pause; unpause in progressfunction with: curl_easy_pause(easy_handle, CURLPAUSE_CONT);
}


static size_t
writefunction(void *ptr, size_t size, size_t nmemb, void *userdata)
{   // handle received data chunk (buffer until curl transport is done)
    size_t realsize = size * nmemb;
    ngx_http_api_ctx_t *api_request = userdata;
    ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s", __FUNCTION__);

    // store chunk in outgoing buffer
    ngx_chain_t *chain_next = ngx_alloc_chain_link(api_request->r->pool);
    ngx_buf_t *buf = ngx_create_temp_buf(api_request->r->pool, realsize);
    chain_next->next = NULL;
    chain_next->buf = buf;

    buf->last = ngx_cpymem(buf->pos, ptr, realsize);
    buf->memory = 1;
    if (api_request->output == NULL)
    {   // set first == last
        api_request->output = api_request->output_end = chain_next;
    }
    else
    {   // append next as last
        ngx_log_error(NGX_LOG_WARN, api_request->r->connection->log, 0, "api: ngx_http_api_request_data_handler called twice");
        api_request->output_end->next = chain_next;
        api_request->output_end = chain_next;
    }

    return realsize;
    // if return value is not size * nmemb, then it generates CURLE_WRITE_ERROR as transfer return value.
    // return CURL_WRITEFUNC_PAUSE to cause writing to this connection to pause (same chunk is passed again); unpause in progressfunction with: curl_easy_pause(easy_handle, CURLPAUSE_CONT);
}

// static size_t
// headerfunction(char *buffer, size_t size, size_t nitems, void *userdata)
// {
//     size_t header_size = nitems * size;
//     ngx_http_api_ctx_t *api_request = userdata;
//     return header_size;
// }

// static int
// progressfunction(void *p, double dltotal, double dlnow, double ult, double uln)
// {
//     ngx_http_api_ctx_t *api_request = p;
//     ngx_log_error(NGX_LOG_DEBUG, log, 0, "Progress: %s (%g/%g)\n", api_request->url, dlnow, dltotal);
//     return 0;
// }

static void
check_multi_info(ngx_http_api_main_conf_t *main_conf)
{
    ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "%s", __FUNCTION__);
    CURLMsg *message;
    int pending;
    while ((message = curl_multi_info_read(main_conf->curlm, &pending)))
    {
        ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "curl_multi_info_read; pending=%d", pending);
        switch(message->msg)
        {
            case CURLMSG_DONE:
            {
                CURLcode result = message->data.result;
                CURL *easy_handle = message->easy_handle;
                ngx_http_api_ctx_t *api_request;
                curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &api_request);
                // char *effective_url;
                // curl_easy_getinfo(easy_handle, CURLINFO_EFFECTIVE_URL, &effective_url);

                // remove request's socket event handlers when curl doesn't issue CURL_POLL_REMOVE when transport is done
                for (api_curl_socket_t *sock = api_request->curl_sockets; sock; sock = sock->next)
                {
                    ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: non-removed sockets on CURLMSG_DONE");
                    sock->done = 1;
                    if (sock->rev.active)
                    {
                        // sock->rev.handler = empty_handler;
                        if (NGX_OK != ngx_del_event(&sock->rev, NGX_READ_EVENT, NGX_CLOSE_EVENT))
                        {
                            ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, ngx_del_event(rev, NGX_READ_EVENT, NGX_CLOSE_EVENT)", __FUNCTION__);
                        }
                    }
                    if (sock->wev.active)
                    {
                        // sock->wev.handler = empty_handler;
                        if (NGX_OK != ngx_del_event(&sock->wev, NGX_WRITE_EVENT, NGX_CLOSE_EVENT))
                        {
                            ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, ngx_del_event(wev, NGX_WRITE_EVENT, NGX_CLOSE_EVENT)", __FUNCTION__);
                        }
                    }
                }

                // CURLMsg* is invalid after calling curl_multi_cleanup, curl_multi_remove_handle or curl_easy_cleanup.
                CURLMcode rc = curl_multi_remove_handle(main_conf->curlm, easy_handle); // remove easy_handle before calling easy_cleanup
                if (rc != CURLM_OK)
                {
                    ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_multi_strerror(rc));
                }
                curl_easy_cleanup(easy_handle);
                api_request->easy_handle = NULL;

                if (result != CURLE_OK)
                {
                    ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "CURLcode = %s, ERRORBUFFER = %s", curl_easy_strerror(result), &api_request->errorbuffer[0]);
                    ngx_http_finalize_request(api_request->r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                }
                else
                {
                    ngx_http_finalize_request(api_request->r, send_response(api_request));
                }
            } break;
            default:
            {
                ngx_log_error(NGX_LOG_ERR, main_conf->log, 0, "%s,  other message->msg", __FUNCTION__);
            } break;
        }
    }
    ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "%s L:%d, pending=%d", __FUNCTION__, __LINE__, pending);
    if (pending == 0 && main_conf->timer.timer_set)
    {
        ngx_del_timer(&main_conf->timer);
    }
}

static void
timer_event_handler(ngx_event_t *timer)
{
    ngx_http_api_main_conf_t *main_conf = timer->data;
    ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "%s", __FUNCTION__);
    int running_handles;
    CURLMcode rc = curl_multi_socket_action(main_conf->curlm, CURL_SOCKET_TIMEOUT, 0, &running_handles);
    if (rc != CURLM_OK)
        ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "curl_multi_strerror = %s", curl_multi_strerror(rc));
    check_multi_info(main_conf);
}

static void
read_event_handler(ngx_event_t *rev)
{
    ngx_connection_t *connection = rev->data;
    ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "api: %s", __FUNCTION__);
    if (!rev->active) // called on close?
    {
        ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "api: !rev->active");
        // return;
        // rev->ready = 0;
        // if (ngx_handle_read_event(rev, 0) != NGX_OK)
        // {
        //     ngx_log_error(NGX_LOG_CRIT, connection->log, 0, "api: ngx_handle_read_event != NGX_OK");
        // }
    }

    ngx_http_api_main_conf_t *main_conf = connection->data;

    int running_handles = 0;
    CURLMcode rc = curl_multi_socket_action(main_conf->curlm, connection->fd, CURL_CSELECT_IN, &running_handles); // running_handles = 0 when all transfers are complete/done
    if (rc != CURLM_OK)
        ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "curl_multi_strerror = %s", curl_multi_strerror(rc));
    check_multi_info(main_conf);

    

    
}

static void
write_event_handler(ngx_event_t *wev)
{
    ngx_connection_t *connection = wev->data;
    ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "api: %s", __FUNCTION__);
    if (!wev->active) // called on close?
    {
        ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "api: !wev->active");
        // return;
        // wev->ready = 0;
        // if (ngx_handle_write_event(wev, 0) != NGX_OK)
        // {
        //     ngx_log_error(NGX_LOG_CRIT, connection->log, 0, "api: %s,  ngx_handle_write_event != NGX_OK", __FUNCTION__);
        // }
    }
    ngx_http_api_main_conf_t *main_conf = connection->data;

    int running_handles = 0;
    CURLMcode rc = curl_multi_socket_action(main_conf->curlm, connection->fd, CURL_CSELECT_OUT, &running_handles);
    if (rc != CURLM_OK)
        ngx_log_error(NGX_LOG_NOTICE, connection->log, 0, "curl_multi_strerror = %s", curl_multi_strerror(rc));
    check_multi_info(main_conf);
}

static int
socketfunction(CURL *easy_handle, curl_socket_t s, int what, void *userp, void *socketp)
{
    ngx_http_api_main_conf_t *main_conf = userp;
    ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "api: %s, what=%d, socketp=%p", __FUNCTION__, what, socketp);
    api_curl_socket_t *sock = socketp;
    ngx_http_api_ctx_t *api_request;
    curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &api_request);

    ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s what=%s", __FUNCTION__,
        what & CURL_POLL_IN ? "CURL_POLL_IN" :
        what & CURL_POLL_OUT ? "CURL_POLL_OUT" :
        what & CURL_POLL_INOUT ? "CURL_POLL_INOUT" :
        what & CURL_POLL_REMOVE ? "CURL_POLL_REMOVE" :
        "?" );

    if (sock) // if socketp is already set, then a previous wait event is being changed/removed
    {
        ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: rev->active==%d, wev->active==%d", sock->rev.active, sock->wev.active);
        int ret = NGX_ERROR;
        if (sock->rev.active)
        {
            // ret = ngx_handle_read_event(&sock->rev, NGX_CLOSE_EVENT);
            // sock->rev.handler = empty_handler;
            ret = ngx_del_event(&sock->rev, NGX_READ_EVENT, 0);
        }
        // ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: ngx_event_flags & NGX_USE_LEVEL_EVENT = %d", ngx_event_flags & NGX_USE_LEVEL_EVENT);
        // if (sock->wev.active && (ngx_event_flags & NGX_USE_LEVEL_EVENT))
        if (sock->wev.active)
        {
            // sock->wev.handler = empty_handler;
            ret = ngx_del_event(&sock->wev, NGX_WRITE_EVENT, 0);
        }

        if (ret != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, ngx_del_event", __FUNCTION__);
            return !CURLM_OK; // handle error on CURLMSG_DONE
        }
    }
    
    if (what == CURL_POLL_REMOVE && sock != NULL)
    {   // remove socket from list
        if (sock == api_request->curl_sockets)
        {   // remove last
            sock = api_request->curl_sockets = NULL;
        }
        else
        {
            api_curl_socket_t *prev = sock->prev;
            api_curl_socket_t *next = sock->next;
            if (prev != NULL)
            {
                prev->next = next;
            }
            if (next != NULL)
            {
                next->prev = prev;
            }
            sock = NULL;
        }
    }
    else
    {
        if (what & CURL_POLL_INOUT)
        {
            // ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, what is CURL_POLL_INOUT", __FUNCTION__);
        }

        if (sock == NULL)
        {   // prepend new socket-struct
            sock = socketp = ngx_pcalloc(api_request->r->pool, sizeof(api_curl_socket_t));
            if (api_request->curl_sockets == NULL)
            {
                api_request->curl_sockets = sock;
            }
            else
            {
                api_request->curl_sockets->prev = sock;
                sock->next = api_request->curl_sockets;
                api_request->curl_sockets = sock;
            }
        }

        ngx_connection_t *connection = &sock->dummy_connection;
        // connection->data = sock;
        connection->data = main_conf;
        connection->read = &sock->rev;
        connection->write = &sock->wev;
        connection->fd = s;
        connection->read->data = connection; // nginx expects ngx_connection_t as event data
        connection->log = api_request->r->connection->log;
        connection->read->log = api_request->r->connection->log;
        connection->write->index = NGX_INVALID_INDEX;
        connection->write->data = connection;
        connection->write->write = 1;
        connection->write->log = api_request->r->connection->log;
        connection->read->index = NGX_INVALID_INDEX;

        int ret = NGX_ERROR;

        if (what & CURL_POLL_IN)
        {
            // ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s, what & CURL_POLL_IN", __FUNCTION__);
            connection->read->handler = read_event_handler; // called when fd is readable
            connection->write->handler = empty_handler; //ngx_http_empty_handler; // ignore when fd is writeable
            ret = ngx_handle_read_event(connection->read, 0);
        }
        else if (what & CURL_POLL_OUT)
        {
            // ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s, what & CURL_POLL_OUT", __FUNCTION__);
            connection->write->handler = write_event_handler; // called when fd is writeable
            connection->read->handler = empty_handler; //ngx_http_empty_handler; // ignore when fd is readable
            ret = ngx_handle_write_event(connection->write, 0);
        }

        if (ret != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, %s", __FUNCTION__, "ngx_handle_write_event/ngx_handle_read_event");
            // curl_easy_cleanup(easy_handle);
            // curl_multi_remove_handle(main_conf->curlm, easy_handle);
            // ngx_http_finalize_request(api_request->r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                // finalize request in check_multi_info
            return !CURLM_OK; // handle error on CURLMSG_DONE
        }
    }

    curl_multi_assign(main_conf->curlm, s, sock); // sets/unsets socketp for next invocation of socketfunction for socket s

    return CURLM_OK;
}

static int
timerfunction(CURLM *multi, long timeout_ms, void *userp)
{   // curl wants to create/clear a timer
    ngx_http_api_main_conf_t *main_conf = userp;
    ngx_log_error(NGX_LOG_NOTICE, main_conf->log, 0, "%s", __FUNCTION__);
    if (timeout_ms >= 0)
    {
        ngx_add_timer(&main_conf->timer, timeout_ms);
    }
    return 0;
}

static ngx_int_t
ngx_http_api_init_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_NOTICE, cycle->log, 0, "%s", __FUNCTION__);

    ngx_http_api_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_api_module);

    if (!main_conf)
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "api: !main_conf");
        return NGX_ERROR;
    }
    
    if (curl_global_init(CURL_GLOBAL_ALL))
    {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "api: Could not init curl");
        return NGX_ERROR;
    }

    main_conf->log = cycle->log;
    main_conf->timer.data = main_conf;
    main_conf->timer.handler = timer_event_handler;
    main_conf->timer.log = cycle->log; // timer event needs log

    main_conf->curlm = curl_multi_init();
    curl_multi_setopt(main_conf->curlm, CURLMOPT_SOCKETFUNCTION, socketfunction); // callback informed about what to wait for.
    curl_multi_setopt(main_conf->curlm, CURLMOPT_SOCKETDATA, main_conf);
    curl_multi_setopt(main_conf->curlm, CURLMOPT_TIMERFUNCTION, timerfunction); // curl requests a specific timeout
    curl_multi_setopt(main_conf->curlm, CURLMOPT_TIMERDATA, main_conf);

    curl_multi_setopt(main_conf->curlm, CURLMOPT_MAXCONNECTS, 10L); // maximum parallel connections

    return NGX_OK;
}

static void
ngx_http_api_exit_process(ngx_cycle_t *cycle)
{
    ngx_log_error(NGX_LOG_WARN, cycle->log, 0, "%s", __FUNCTION__);

    ngx_http_api_main_conf_t *main_conf = ngx_http_cycle_get_module_main_conf(cycle, ngx_http_api_module);

    curl_multi_cleanup(main_conf->curlm);
    curl_global_cleanup();
}


static ngx_int_t
api_request_start(ngx_http_api_ctx_t *api_request)
{
    ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s", __FUNCTION__);

    ngx_http_api_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(api_request->r, ngx_http_api_module);
    ngx_http_api_main_conf_t *main_conf = ngx_http_get_module_main_conf(api_request->r, ngx_http_api_module);
    if (loc_conf == NULL || main_conf == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: loc_conf == NULL || main_conf == NULL");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    CURL *easy_handle = curl_easy_init();
    if (!easy_handle)
    {
        ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: easy_handle == NULL");
        return NGX_ERROR;
    }
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    api_request->easy_handle = easy_handle;

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    ngx_pool_cleanup_t *cln = ngx_pool_cleanup_add(api_request->r->pool, 0);
    if (NULL == cln)
    {
        return NGX_ERROR;
    }
    cln->handler = request_cleanup; // set request's cleanup callback
    cln->data = api_request; // handler argument
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);


    api_request->httpheader = curl_slist_append(NULL, "Expect:");
    if (api_request->httpheader == NULL)
    {
        ngx_log_error(NGX_LOG_ERR, api_request->r->connection->log, 0, "api: %s, api_request->httpheader == NULL ", __FUNCTION__);
    }

    {CURLcode rc;

    // https://curl.se/libcurl/c/curl_easy_setopt.html

    // curl_easy_setopt(easy_handle, CURLOPT_STDERR, );
    // curl_easy_setopt(easy_handle, CURLOPT_NOPROGRESS, 0L);
    // curl_easy_setopt(easy_handle, CURLOPT_PROGRESSFUNCTION, progressfunction);
    // curl_easy_setopt(easy_handle, CURLOPT_PROGRESSDATA, api_request);
    // curl_easy_setopt(easy_handle, CURLOPT_ERRORBUFFER, &api_request->error_buffer);
    // curl_easy_setopt(http_handle, CURLOPT_DEBUGFUNCTION, debugfunction);
    // curl_easy_setopt(curl, CURLOPT_DEBUGDATA, &my_tracedata); // passed to debugfunction
    rc = curl_easy_setopt(easy_handle, CURLOPT_VERBOSE, 1L); // enable DEBUGFUNCTION
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    // curl_easy_setopt(easy_handle, CURLOPT_LOW_SPEED_TIME, 3L); // 3 second duration limit for low speed.
    // curl_easy_setopt(easy_handle, CURLOPT_LOW_SPEED_LIMIT, 10L); // 10 B/s lower limit before CURLE_OPERATION_TIMEDOUT
    // curl_easy_setopt(easy_handle, CURLOPT_TIMEOUT, 180L); // timeout; includes name-lookups and queuing of multiple handles

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    rc = curl_easy_setopt(easy_handle, CURLOPT_FOLLOWLOCATION, 1L);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    // curl_easy_setopt(easy_handle, CURLOPT_REDIRPROTOCOL, ); // which protocols to auto-redirect to
    // curl_easy_setopt(easy_handle, CURLOPT_PROTOCOLS, ); // only allow specific protocols (e.g. don't re-direct to non-HTTPS)

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    // curl_easy_setopt(easy_handle, CURLOPT_CUSTOMREQUEST, ); // like -X, set when non-implied HTTP method should be used (overrides automatic redirect method)
    rc = curl_easy_setopt(easy_handle, CURLOPT_CONNECTTIMEOUT, 10L);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    // loc_conf->url is ngx_str_t, and not zero-terminated
    rc = curl_easy_setopt(easy_handle, CURLOPT_URL, "http://localhost:8888/test"); // 
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    rc = curl_easy_setopt(easy_handle, CURLOPT_HTTPHEADER, api_request->httpheader);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    rc = curl_easy_setopt(easy_handle, CURLOPT_READFUNCTION, readfunction);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    rc = curl_easy_setopt(easy_handle, CURLOPT_READDATA, api_request);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    rc = curl_easy_setopt(easy_handle, CURLOPT_WRITEFUNCTION, writefunction); // write back response
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    rc = curl_easy_setopt(easy_handle, CURLOPT_WRITEDATA, api_request);
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    // curl_easy_setopt(easy_handle, CURLOPT_HEADERFUNCTION, headerfunction);
    // curl_easy_setopt(easy_handle, CURLOPT_HEADERDATA, api_request);
    // curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE_LARGE, length_of_data);
    // curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDSIZE, length_of_data); // If you post more than 2GB, use CURLOPT_POSTFIELDSIZE_LARGE. 
    // curl_easy_setopt(easy_handle, CURLOPT_POSTFIELDS, data);
    rc = curl_easy_setopt(easy_handle, CURLOPT_PRIVATE, api_request); // curl_easy_getinfo(easy_handle, CURLINFO_PRIVATE, &api_request_data), used after event-triggered curl_multi_socket_action
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    rc = curl_easy_setopt(easy_handle, CURLOPT_FRESH_CONNECT, 1L); // don't reuse a connection
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    rc = curl_easy_setopt(easy_handle, CURLOPT_FORBID_REUSE, 1L); // close connection after use
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    // curl_easy_setopt(easy_handle, CURLOPT_SSLCERT, "client.pem");
    // curl_easy_setopt(easy_handle, CURLOPT_SSLKEY, "key.pem");
    // curl_easy_setopt(easy_handle, CURLOPT_KEYPASSWD, "s3cret");

    // struct curl_blob stblob;
    // stblob.data = certificateData;
    // stblob.len = filesize;
    // stblob.flags = CURL_BLOB_COPY;
    // curl_easy_setopt(easy_handle, CURLOPT_SSLCERT_BLOB, &stblob);
    // curl_easy_setopt(easy_handle, CURLOPT_SSLCERTTYPE, "P12");
    // curl_easy_setopt(easy_handle, CURLOPT_KEYPASSWD, "s3cret");

    // curl_easy_setopt(easy_handle, CURLOPT_CAPATH, "/etc/cert-dir");
    rc = curl_easy_setopt(easy_handle, CURLOPT_SSL_VERIFYPEER, 0L); // -K
    if (rc != CURLE_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_easy_strerror(rc));
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    // curl_easy_setopt(easy_handle, CURLOPT_SSL_VERIFYSTATUS, 0L);

    // struct curl_slist *resolve = curl_slist_append(NULL, "example.com:80:127.0.0.1");
    // curl_easy_setopt(curl, CURLOPT_RESOLVE, resolve);
    }

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    CURLMcode rc = curl_multi_add_handle(main_conf->curlm, easy_handle);
    if (rc != CURLM_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_multi_strerror(rc));
    int running = 0;
    rc = curl_multi_socket_action(main_conf->curlm, CURL_SOCKET_TIMEOUT, 0, &running); // start
    if (rc != CURLM_OK)
        ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_multi_strerror(rc));

    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);
    check_multi_info(main_conf);
    ngx_log_error(NGX_LOG_DEBUG, api_request->r->connection->log, 0, "api: %s L:%d", __FUNCTION__, __LINE__);

    return NGX_AGAIN;
}

static void
request_cleanup(void *data)
{
    ngx_http_api_ctx_t *api_request = data;
    ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: %s", __FUNCTION__);
    // ngx_http_api_loc_conf_t *loc_conf = ngx_http_get_module_loc_conf(api_request->r, ngx_http_api_module);
    ngx_http_api_main_conf_t *main_conf = ngx_http_get_module_main_conf(api_request->r, ngx_http_api_module);

    if (api_request->easy_handle)
    {
        CURLMcode rc = curl_multi_remove_handle(main_conf->curlm, api_request->easy_handle); // remove easy_handle before calling easy_cleanup
        if (rc != CURLM_OK)
        {
            ngx_log_error(NGX_LOG_CRIT, api_request->r->connection->log, 0, "%s", curl_multi_strerror(rc));
        }
        curl_easy_cleanup(api_request->easy_handle);
    }

    curl_slist_free_all(api_request->httpheader);
    // curl_slist_free_all(api_request->resolve);
}


//
// REQUEST HANDLER
// ---------------
// Entry-point callback for each HTTP request. Only accepts GET and POST.
//
static ngx_int_t
ngx_http_api_request_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0, "api: %s pid=%d", __FUNCTION__, ngx_pid);

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_POST)))
    {
        return NGX_HTTP_NOT_ALLOWED;
    }
    ngx_http_api_ctx_t *api_request = ngx_pcalloc(r->pool, sizeof(ngx_http_api_ctx_t)); // NOTE: zero-initialized
    if (api_request == NULL)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_http_set_ctx(r, api_request, ngx_http_api_module); // makes context retrievable from r with ngx_http_get_module_ctx(r, ngx_http_api_module)
    api_request->r = r;

    ngx_int_t ret;
    if ((ret = process_request_parameters(r, api_request)) != NGX_OK)
    {
        return ret;
    }

    if ((r->method & NGX_HTTP_GET) && ngx_http_discard_request_body(r) != NGX_OK)
    {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ret = ngx_http_read_client_request_body(r, ngx_http_api_request_data_handler); // delegates to body handler callback
    if (ret >= NGX_HTTP_SPECIAL_RESPONSE)
    {
        return ret;
    }
    return NGX_DONE; // doesn't destroy request until ngx_http_finalize_request is called
}

static ngx_int_t
process_request_parameters(ngx_http_request_t *r, ngx_http_api_ctx_t *api_request)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: url = '%V'", &r->unparsed_uri);

    if (r->headers_in.content_type)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: content-type = '%V'", &r->headers_in.content_type->value);
        api_request->content_type.data = r->headers_in.content_type->value.data;
        api_request->content_type.len = r->headers_in.content_type->value.len;
    }

    if (r->headers_in.content_length_n)
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: content-length = '%O'", r->headers_in.content_length_n);
    }

    return NGX_OK;
}

static void
ngx_http_api_request_data_handler(ngx_http_request_t *r)
{
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: %s", __FUNCTION__);

    ngx_http_api_ctx_t *api_request = ngx_http_get_module_ctx(r, ngx_http_api_module);

    for (ngx_chain_t *cl = r->request_body->bufs; cl; cl = cl->next)
    {
        ngx_str_t str = {ngx_buf_size(cl->buf), cl->buf->pos};
        ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: buffer = '[%V]'", &str);

        off_t buffer_size = ngx_buf_size(cl->buf);
        ngx_buf_t *buf = ngx_create_temp_buf(r->pool, buffer_size);
        ngx_chain_t *chain_next = ngx_alloc_chain_link(r->pool);
        if (chain_next == NULL || buf == NULL)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "api: %s, chain_next == NULL || buf == NULL", __FUNCTION__);
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
            return;
        }

        if (cl->buf->in_file || cl->buf->temp_file) // if buffered in file, then read entire file into a buffer
        {
            ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: buffer in file");
            ssize_t bytes_read = ngx_read_file(cl->buf->file, buf->pos, buffer_size, cl->buf->file_pos);
            if (bytes_read != (ssize_t)buffer_size)
            {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "api: error reading tempfile; ret=%zu", bytes_read);
                ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
                return;
            }
            chain_next->buf->last = buf->pos + bytes_read;
        }
        else
        {
            chain_next->buf->last = ngx_cpymem(buf->pos, cl->buf->pos, buffer_size);
        }

        chain_next->next = NULL;
        buf->last_buf = cl->buf->last_buf;
        chain_next->buf = buf;
        if (api_request->input == NULL)
        {   // set first == last
            api_request->input = api_request->input_end = chain_next;
        }
        else
        {   // append next as last
            api_request->input_end->next = chain_next;
            api_request->input_end = chain_next;
        }
    }

    if (api_request->easy_handle == NULL)
    {
        // or wait until last_buf; depends on configuration and runtime input
        ngx_int_t ret = api_request_start(api_request);
        if (ret == NGX_ERROR)
        {
            ngx_http_finalize_request(r, NGX_HTTP_INTERNAL_SERVER_ERROR);
        }
        else if (ret == NGX_OK)
        {   // finalize right away on OK
            ngx_http_finalize_request(r, send_response(api_request));
        }
        // else NGX_AGAIN to finalize later
    }
    else
    {   // un-pause readfunction since more data is available now
        ngx_log_error(NGX_LOG_NOTICE, api_request->r->connection->log, 0, "api: chunk");
        curl_easy_pause(api_request->easy_handle, CURLPAUSE_CONT);
    }
}

static ngx_int_t
send_response(ngx_http_api_ctx_t *api_request)
{
    ngx_http_request_t *r = api_request->r;
    ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: %s", __FUNCTION__);

    if (api_request->output)
    {
        ngx_str_t str = {ngx_buf_size(api_request->output->buf), api_request->output->buf->pos};
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: output buffer0 = '%V'", &str);
    }
    else
    {
        ngx_log_error(NGX_LOG_NOTICE, r->connection->log, 0, "api: output buffer0 = ''");
    }

    off_t content_length = 0;
    for (ngx_chain_t *cl = api_request->output; cl; cl = cl->next)
    {
        content_length += ngx_buf_size(cl->buf);
        if (cl->next == NULL)
        {
            cl->buf->last_in_chain = 1;
            cl->buf->last_buf = 1;
        }
    }

    r->headers_out.content_length_n = content_length;
    r->headers_out.content_type.len = sizeof "text/plain" - 1;
    r->headers_out.content_type.data = ngx_palloc(r->pool, r->headers_out.content_type.len);
    ngx_memcpy(r->headers_out.content_type.data, "text/plain", r->headers_out.content_type.len);
    r->headers_out.status = NGX_HTTP_OK;

    if (ngx_http_send_header(r) != NGX_OK)
    {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "api: ngx_http_send_header(r) != NGX_OK");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    if (content_length != 0)
    {
        if (ngx_http_output_filter(r, api_request->output) != NGX_OK)
        {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "api: ngx_http_output_filter() != NGX_OK");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }
    }

    return r->headers_out.status;
}
