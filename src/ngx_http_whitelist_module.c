#include "ngx_http_whitelist_module.h"

/******************************************************************[ hooks ]***/


/*
 * Define the following four commands:
 *  1) whitelist                    - set a whitelist for a given key, ip, 
 *                                      and header. If whitelist_set_header_name
 *                                      is defined the contents of the "header"
 *                                      parameter will be set as a request
 *                                      header before being passed on to the
 *                                      backend
 *
 *  2) whitelist_check_param        - specify the name of a parameter in the
 *                                      request to check the key against
 *
 *  3) whitelist_check_header       - specify the name of a request header
 *                                      to check the key against
 *
 *  4) whitelist_set_header_name    - specify the name of the request header to
 *                                      set with "header=" data specified in the
 *                                      whitelist command
 */
static ngx_command_t  ngx_http_whitelist_commands[] = {
    { ngx_string("whitelist"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_http_whitelist_rule,
      NGX_HTTP_LOC_CONF_OFFSET,
      0,
      NULL },

    { ngx_string("whitelist_check_param"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_whitelist_loc_conf_t, check_param),
      NULL },

    { ngx_string("whitelist_check_header"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_whitelist_loc_conf_t, check_header),
      NULL },

    { ngx_string("whitelist_set_header_name"),
      NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_whitelist_loc_conf_t, set_header),
      NULL },

    ngx_null_command
};

/*
 * Configure nginx - 
 */
static ngx_http_module_t  ngx_http_whitelist_module_ctx = {
    NULL,                                   /* preconfiguration */
    ngx_http_whitelist_init,                /* postconfiguration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    NULL,                                   /* create main configuration */
    NULL,                                   /* init main configuration */

    ngx_http_whitelist_create_loc_conf,     /* create location configuration */
    ngx_http_whitelist_merge_loc_conf       /* merge location configuration */
};
 
/*
 * Configure nginx to use this module
 */
ngx_module_t  ngx_http_whitelist_module = {
    NGX_MODULE_V1,
    &ngx_http_whitelist_module_ctx,         /* module context */
    ngx_http_whitelist_commands,            /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


/**************************************************************[ functions ]***/


static char *
ngx_http_whitelist_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_whitelist_loc_conf_t *wlcf = conf;
    ngx_int_t                       rc;
    ngx_cidr_t                      cidr;
    ngx_str_t                       *value, *key, *header, *ip;
    ngx_http_whitelist_rule_t     *rule;
    ngx_uint_t                      i;
    
    /*
     * Setup the rules hash if one does not already exist
     */
    
    /*
     * Get the command args and set the appropriate data
     */
    ngx_str_null(key);
    ngx_str_null(ip);
    ngx_str_null(header);
     
    value = cf->args->elts;
    
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            key->data = value[i].data + 4;
            key->len = value[i].len - 4;
        }
        
        if (ngx_strncmp(value[i].data, "ip=", 3) == 0) {
            ip->data = value[i].data + 3;
            ip->len = value[i].len - 3;
        }
        
        if (ngx_strncmp(value[i].data, "header=", 7) == 0) {
            header->data = value[i].data + 7;
            header->len = value[i].len - 7;
        }
    }
    
    /*
     * Read the ip address in with ngx_ptocidr to verify valid data
     */
    ngx_memzero(&cidr, sizeof(ngx_cidr_t));
    rc = ngx_ptocidr(ip, &cidr);
    
    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid ip address parameter \"%V\"", &ip);
        return NGX_CONF_ERROR;
    }
    else if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                     "low address bits of %V are meaningless", &ip);
    }
    
    if (wlcf->rules == NULL) {
        wlcf->rules = ngx_array_create(cf->pool, 4,
                                       sizeof(ngx_http_whitelist_rule_t));
        if (wlcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }
    }
    
    key_hash_pair *pair;
    pair = ngx_alloc(sizeof(key_hash_pair), cf->log);
    pair->key.data = ngx_alloc(sizeof(char) * MAX_KEY_STR_LEN, cf->log);
    build_key_hash_pair(pair, key, ip);
    
    /*
     * Find or create a rule for this request key
     */
    rule = find_whitelist_rule(wlcf->rules, pair);
    if (rule == NULL) {
        rule = ngx_array_push(wlcf->rules);
        if (rule == NULL) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Unable to add whitelist rule for params: "
                               "key=%s, ip=%s, header=%s", key->data, ip->data,
                               header->data);
            return NGX_CONF_ERROR;
        }

        rule->key_pair = pair;
        rule->header = header;
    }
    else if (ngx_strcmp(rule->header->data, header->data)) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Whitelist rule already exists: "
                           "key=%s, ip=%s, prev_header=%s, new_header=%s",
                           key->data, ip->data, rule->header, header->data);
        
        return NGX_CONF_ERROR;
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_whitelist_handler(ngx_http_request_t *r)
{
    ngx_http_whitelist_loc_conf_t   *wlcf;
    struct sockaddr_in              *sin;
    ngx_http_whitelist_rule_t          *rule;
    ngx_str_t                       *header, *key, *ip;
    ngx_table_elt_t                 *new_header;
        
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_whitelist_module);
    
    /*
     * Populate the ip data from the request
     */
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        if (wlcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            ngx_str_set(ip, inet_ntoa(sin->sin_addr));
        }
        break;
    }
    
    /*
     * Populate the key data from the request
     */
    key = get_key_from_request(wlcf, r);
    
    if (key->data == NULL) {
        ngx_log_error(NGX_LOG_EMERG, r->connection->log, 0,
                           "Unable to get whitelist key from request, "
                           "neither param nor header values were found.");
                           
       return NGX_DECLINED;
    }

    key_hash_pair *pair;
    pair = ngx_alloc(sizeof(key_hash_pair), r->connection->log);
    pair->key.data = ngx_alloc(sizeof(char) * MAX_KEY_STR_LEN,
        r->connection->log);
    build_key_hash_pair(pair, key, ip);

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Checking for whitelist rule: "
                    "key=%s, ip=%s", key->data, ip->data);

    /*
     * If a matching rule is found for this ip and key combination
     * populate the header data and let things pass
     */
    rule = find_whitelist_rule(wlcf->rules, pair);
    if (rule != NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Rule Found");
        
        new_header = ngx_list_push(&r->headers_out.headers);
        if (new_header == NULL) {
            return NGX_ERROR;
        }

        ngx_str_set(&(new_header->key), wlcf->set_header->data);
        ngx_str_set(&(new_header->value), rule->header->data);
        new_header->hash = ngx_hash_key_lc(new_header->value.data,
                                            new_header->value.len);
        
        return NGX_OK; 
    }
    
    /*
     * Otherwise log a warning and decline the request
     */
    ngx_log_error(NGX_LOG_WARN, r->connection->log, 0,
                       "Request denied by whitelist rules: "
                       "key=%s, ip=%s", key->data, ip->data, header->data);

    return NGX_DECLINED;
}

static void *
ngx_http_whitelist_create_loc_conf(ngx_conf_t *cf)
{
    ngx_http_whitelist_loc_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_whitelist_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    return conf;
}


static char *
ngx_http_whitelist_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_whitelist_loc_conf_t  *prev = parent;
    ngx_http_whitelist_loc_conf_t  *conf = child;

    if (conf->rules == NULL) {
        conf->rules = prev->rules;
    }
    
    /*
     * Halt server startup if we didn't get a check_param or check_header
     */
    if (conf->check_param == NULL && conf->check_header == NULL)
    {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "The whitelist configuration must have either a"
                           " request parameter (use whitelist_check_param)"
                           " or header (use whitelist_header_param)"
                           " which will contain the whitelisted key"
                           " in order to properly whitelist requests");
        
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_whitelist_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_whitelist_handler;

    return NGX_OK;
}

static void
build_key_hash_pair(key_hash_pair *h, ngx_str_t *api_key, ngx_str_t *ip)
{
    memset(h->key.data, 0, sizeof(h->key.data));
    strcat((char *)h->key.data, (char *)api_key->data);
    strcat((char *)h->key.data, (char *)ip->data);
    h->key.len = (strlen((char *)h->key.data) - 1);
    h->hash = ngx_hash_key_lc(h->key.data, h->key.len);
}

static ngx_str_t *
get_key_from_request(ngx_http_whitelist_loc_conf_t *wlcf, ngx_http_request_t *r)
{
    ngx_uint_t                  i;
    ngx_int_t                   key;
    ngx_list_part_t             *part;
    ngx_http_variable_value_t   *vv;
    ngx_table_elt_t             *header;
    ngx_str_t                   *found_key;
    
    key = 0;
    ngx_str_null(found_key);

    /*
     * Fetch the value of the check_param parameter out of the request
     * (e.g. k=THE_KEY)
     */
    if (wlcf->check_param != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "getting value from param \"%V\"", &(wlcf->check_param));

        key = ngx_hash_strlow(wlcf->check_param->data, wlcf->check_param->data,
            wlcf->check_param->len);
        
        vv = ngx_http_get_variable(r, wlcf->check_param, key);
        if (vv != NULL && vv->valid == 1) {
            ngx_str_set(found_key, vv->data);
        }
    }
    
    /*
     * If we haven't gotten a value from the parameter, fetch the value of the
     * check_header header out of the request (e.g. X-REQUEST_KEY=THE_KEY)
     */
    if (found_key->data == NULL && wlcf->check_header != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "getting value from header \"%V\"",
                       &(wlcf->check_header));
        
        part = &r->headers_in.headers.part;
        header = part->elts;

        for (i = 0 ;; i++) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                header = part->elts;
                i = 0;
            }
            
            if (ngx_strcmp(header[i].key.data, wlcf->check_header->data) == 0) {
                ngx_str_set(found_key, header[i].value.data);
                break;
            }
        }
    }
    
    return found_key;
}

static ngx_http_whitelist_rule_t *
find_whitelist_rule(ngx_array_t *rules, key_hash_pair *pair)
{
    ngx_uint_t               i;
    ngx_http_whitelist_rule_t  *rule;

    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                   "find rule: %d", pair->hash);

    rule = rules->elts;
    for (i = 0; i < rules->nelts; i++) {

        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "rule: %d", rule[i]->key_pair.hash);

        if (pair->hash == rule[i].key_pair->hash) {
            return rule[i];
        }
    }
    
    return NULL;
}
