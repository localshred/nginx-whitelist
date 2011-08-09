/*
 * nginx HTTP Whitelist Module 
 *   Provide finer-grained control for allowing/denying requests based on a key
 *   provided in the request alongisde a paired ip address. Also provides pass-
 *   through capabilities for sending a header through when a rule is matched.
 *
 * Copyright (C) by localshred (bj.neilsen@gmail.com)
 */
 
#ifndef NGX_HTTP_WHITELIST_MODULE_H
#define NGX_HTTP_WHITELIST_MODULE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


/*****************************************************************[ config ]***/


#define MAX_KEY_STR_LEN     56

/*
 * Configuration structure which holds whitelist rules,
 * the request parameter name to check (if any),
 * the request header name to check (if any),
 * and optionally a header name to set arbitrary data on successful validation
 */
typedef struct {
    ngx_array_t     *rules;
    ngx_str_t       *check_param;
    ngx_str_t       *check_header;
    ngx_str_t       *set_header;
} ngx_http_whitelist_loc_conf_t;


typedef struct {
    ngx_uint_t              hash;
    ngx_str_t               key;
} key_hash_pair;

typedef struct {
    key_hash_pair           *key_pair;
    ngx_str_t               *header;
} ngx_http_whitelist_rule_t;


/*************************************************************[ signatures ]***/


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
static void build_key_hash_pair(key_hash_pair *h, ngx_str_t api_key,
    ngx_str_t ip);

/*
 * Get the hashed key value from the request, by parameter first, then header.
 * NULL value indicates not found.
 */
static ngx_str_t get_key_from_request(ngx_http_whitelist_loc_conf_t *wlcf,
    ngx_http_request_t *r);

/*
 * Find a rule in the rules array based on the hash pair given.
 */
static ngx_http_whitelist_rule_t *
find_whitelist_rule(ngx_array_t *rules, key_hash_pair *pair, ngx_log_t *log);

    
#endif /* NGX_HTTP_WHITELIST_MODULE_H */
