/*
 * HTTP API Whitelist
 */

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*************************************************************
 * Config Structures
 **************************************************************/

 
#define NO_DATA             "NO_DATA";
#define MAX_KEY_STR_LEN     56

/*
 * Configuration structure which holds whitelist rules,
 * the request parameter name to check (if any),
 * the request header name to check (if any),
 * and optionally a header name to set arbitrary data on successful validation
 */
typedef struct {
    ngx_hash_keys_arrays_t  *rules;
    ngx_str_t               *check_param;
    ngx_str_t               *check_header;
    ngx_str_t               *set_header;
} ngx_http_whitelist_loc_conf_t;


typedef struct {
    ngx_uint_t              hash;
    ngx_str_t               key;
} key_hash_pair;


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


/*************************************************************
 * Functions
 **************************************************************/


 /*
  * Set a whitelist rule, e.g.:
  *
  *      whitelist key=5275481fce3f2919fbbb8c95847c1001                  \
  *                  ip=208.53.44.220                                    \
  *                  header=ASR-2f42f09c-2749-25b5-eafe-588f5995dc6b;
  *
  */
static char *ngx_http_whitelist_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);

/*
 * Handle request forward/drop based on whitelist rules
 */
static ngx_int_t ngx_http_whitelist_handler(ngx_http_request_t *r);
    
/*
 * Create the configuration struct
 */
static void *ngx_http_whitelist_create_loc_conf(ngx_conf_t *cf);

/*
 * Merge the configuration struct with a previously created struct
 */
static char *ngx_http_whitelist_merge_loc_conf(ngx_conf_t *cf, void *parent,
    void *child);

/*
 * Define the request handler
 */
static ngx_int_t ngx_http_whitelist_init(ngx_conf_t *cf);

/*
 * Takes an allocated hash pair, the api key, and the ip
 * Builds an appropriate hash out of the key and ip
 */
void build_key_hash_pair(key_hash_pair *h, ngx_str_t api_key, ngx_str_t ip);

static char *
ngx_http_whitelist_rule(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf)
{
    ngx_http_whitelist_loc_conf_t *wlcf = conf;

    ngx_int_t           rc;
    ngx_cidr_t          cidr;
    ngx_str_t           *value, key, header, ip;
    
    /*
     * Setup the rules hash if one does not already exist
     */
    if (wlcf->rules == NULL) {
        wlcf->rules = ngx_pcalloc(cf->temp_pool,
                                    sizeof(ngx_hash_keys_arrays_t));
        if (wlcf->rules == NULL) {
            return NGX_CONF_ERROR;
        }

        wlcf->rules.pool = cf->pool;
        wlcf->rules.temp_pool = cf->temp_pool;

        if (ngx_hash_keys_array_init(wlcf->rules, NGX_HASH_SMALL) != NGX_OK) {
            return NGX_CONF_ERROR;
        }
    }
    
    /*
     * Get the command args and set the appropriate data
     */
    value = cf->args->elts;
    
    ngx_uint_t i;
    for (i = 1; i < cf->args->nelts; i++) {
        if (ngx_strncmp(value[i].data, "key=", 4) == 0) {
            key.data = value[i].data + 4;
            key.len = strlen(key.data) - 1;
        }
        
        if (ngx_strncmp(value[i].data, "ip=", 3) == 0) {
            ip.data = value[i].data + 3;
            ip.len = strlen(ip.data) - 1;
        }
        
        if (ngx_strncmp(value[i].data, "header=", 7) == 0) {
            header.data = value[i].data + 7;
            header.len = strlen(header.data) - 1;
        }
    }
    
    /*
     * Read the ip address in with ngx_ptocidr to verify valid data
     */
    ngx_memzero(&cidr, sizeof(ngx_cidr_t));
    rc = ngx_ptocidr(&ip, &cidr);
    
    if (rc == NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                     "invalid ip address parameter \"%V\"", &ip);
        return NGX_CONF_ERROR;
    }

    if (rc == NGX_DONE) {
        ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                     "low address bits of %V are meaningless", &ip);
    }
    
    key_hash_pair *pair;
    pair = malloc(sizeof(key_hash_pair));
    pair->key.data = malloc(sizeof(char) * MAX_KEY_STR_LEN);
    build_key_hash_pair(pair, key, ip);
    
    /*
     * Find or create a rule for this request key
     */
    if (ngx_hash_find(wlcf->rules, pair->hash, pair->key.data, pair->key.len) == NULL) {
        // Create a new empty rule
        if (header == NULL) {
            header.len = strlen(NO_DATA) - 1;
            header.data = NO_DATA;
        }
        rc = ngx_hash_add_key(wlcf->rules, &pair->key, &header, NGX_HASH_READONLY_KEY);
        if (rc != NGX_OK) {
            ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                               "Unable to add whitelist rule for params: "
                               "key=%s, ip=%s, header=%s", key.data, ip.data,
                               header.data);
            return NGX_CONF_ERROR;
        }
    }
    else {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Whitelist rule already exists for params: "
                           "key=%s, ip=%s, header=%s", key.data, ip.data,
                           header.data);
        return NGX_CONF_ERROR;
    }
    
    return NGX_OK;
}

static ngx_int_t
ngx_http_whitelist_handler(ngx_http_request_t *r)
{
    ngx_http_whitelist_loc_conf_t   *wlcf;
    struct sockaddr_in              *sin;
    ngx_str_t                       header, key, *ip;
    ngx_uint_t                      i;
    
    wlcf = ngx_http_get_module_loc_conf(r, ngx_http_whitelist_module);
    
    /*
     * Populate the ip data from the request
     */
    switch (r->connection->sockaddr->sa_family) {
    case AF_INET:
        if (wlcf->rules) {
            sin = (struct sockaddr_in *) r->connection->sockaddr;
            ngx_str_set(&ip, *inet_ntoa(sin->sin_addr));
        }
        break;
    }
    
    /*
     * TODO Populate the key data from the request
     */
    ngx_http_whitelist_get_request_parameter();

    key_hash_pair *pair;
    pair = malloc(sizeof(key_hash_pair));
    pair->key.data = malloc(sizeof(char) * MAX_KEY_STR_LEN);
    build_key_hash_pair(pair, key, ip);

    ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                    "Checking for whitelist rule: "
                    "key=%s, ip=%s", key.data, ip.data);

    /*
     * If a matching rule is found for this ip and key combination
     * populate the header data and let things pass
     */
    if (ngx_hash_find(wlcf->rules, pair->hash, pair->key.data,
            pair->key.len) != NULL) {
                
        ngx_log_debug3(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Rule Found");

        /*
         * TODO Populate the header
         */
        
        return NGX_OK; 
    }
    
    /*
     * Otherwise log a warning and decline the request
     */
    ngx_conf_log_error(NGX_LOG_WARN, cf, 0,
                       "Request denied by whitelist rules: "
                       "key=%s, ip=%s", key.data, ip.data, header.data);

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

void
build_key_hash_pair(key_hash_pair *h, ngx_str_t api_key, ngx_str_t ip)
{
    memset(h->key.data, 0, sizeof(h->key.data));
    strcat(h->key.data, api_key.data);
    strcat(h->key.data, ip.data);
    h->key.len = (strlen(h->key.data) - 1);
    
    ngx_uint_t i;
    for (i = 0; i < (int)h->key.len; i++) {
        h->hash = ngx_hash(&h->hash, h->key.data[i]);
    }
}

ngx_http_variable_value_t
get_key_from_request(ngx_http_whitelist_loc_conf_t *wlcf, ngx_http_request_t *r)
{
    ngx_int_t                   key;
    ngx_http_variable_value_t  *vv;
    
    if (wlcf->check_param != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "getting value from param \"%V\"", wlcf->check_param);

        key = ngx_hash_strlow(wlcf->check_param.data, wlcf->check_param.data, wlcf->check_param.len);
        
        vv = ngx_http_get_variable(r, wlcf->check_param, key);
    }
    
    if (vv == NULL && wlcf->check_header != NULL) {
        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0,
                       "getting value from header \"%V\"", wlcf->check_param);
        
        
    }
    
    if (vv == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "Unable to get whitelist key from request, "
                           "neither param nor header values were found.");
    }
    
    return vv;
}
