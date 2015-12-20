local ffi          = require "ffi"
local ffi_cast     = ffi.cast
local ffi_cdef     = ffi.cdef
local ffi_string   = ffi.string
local pcre         = ffi.load("pcre")
local r3           = ffi.load("r3")
local string_len   = string.len
local string_upper = string.upper
local table_insert = table.insert
local unpack = unpack or table.unpack

ffi_cdef[[
typedef struct real_pcre pcre;
typedef struct pcre_extra pcre_extra;

struct _edge;
struct _node;
struct _route;
typedef struct _edge edge;
typedef struct _node node;
typedef struct _route route;

typedef struct _str_array {
  char **tokens;
  int    len;
  int    cap;
} str_array;

struct _node {
    edge  ** edges;
    // edge  ** edge_table;

    // edges are mostly less than 255
    unsigned char    compare_type; // compare_type: pcre, opcode, string
    unsigned char    edge_len;
    unsigned char    endpoint; // endpoint, should be zero for non-endpoint nodes
    unsigned char    ov_cnt; // capture vector array size for pcre

    // almost less than 255
    unsigned char      edge_cap;
    unsigned char      route_len;
    unsigned char      route_cap;
    // <-- here comes a char[1] struct padding for alignment since we have 4 char above.


    /** compile-time variables here.... **/

    /* the combined regexp pattern string from pattern_tokens */
    pcre * pcre_pattern;
    pcre_extra * pcre_extra;

    route ** routes;

    char * combined_pattern;

    /**
     * the pointer of route data
     */
    void * data;
};

struct _edge {
    char * pattern; // 8 bytes
    node * child; // 8 bytes
    unsigned char  pattern_len; // 1 byte
    unsigned char  opcode:4; // 4 bit
    unsigned char  has_slug:1; // 1 bit
};

struct _route {
    char * path;
    int    path_len;

    int    request_method; // can be (GET || POST)

    char * host; // required host name
    int    host_len;

    void * data;

    char * remote_addr_pattern;
    int    remote_addr_pattern_len;
};

typedef struct {
    str_array * vars;
    const char * path; // current path to dispatch
    int    path_len; // the length of the current path
    int    request_method;  // current request method

    void * data; // route ptr

    char * host; // the request host
    int    host_len;

    char * remote_addr;
    int    remote_addr_len;
} match_entry;

str_array * str_array_create(int cap);

bool str_array_is_full(const str_array * l);

bool str_array_resize(str_array *l, int new_cap);

bool str_array_append(str_array * list, char * token);

void str_array_free(str_array *l);

void str_array_dump(const str_array *l);

str_array * split_route_pattern(char *pattern, int pattern_len);


node * r3_tree_create(int cap);

node * r3_node_create();

void r3_tree_free(node * tree);

edge * r3_node_connectl(node * n, const char * pat, int len, int strdup, node *child);

edge * r3_node_find_edge(const node * n, const char * pat, int pat_len);

void r3_node_append_edge(node *n, edge *child);


edge * r3_node_find_common_prefix(node *n, const char *path, int path_len, int *prefix_len, char **errstr);

node * r3_tree_insert_pathl(node *tree, const char *path, int path_len, void * data);



route * r3_tree_insert_routel(node *tree, int method, const char *path, int path_len, void *data);

route * r3_tree_insert_routel_ex(node *tree, int method, const char *path, int path_len, void *data, char **errstr);



node * r3_tree_insert_pathl_ex(node *tree, const char *path, int path_len, route * route, void * data, char ** errstr);

void r3_tree_dump(const node * n, int level);


edge * r3_node_find_edge_str(const node * n, const char * str, int str_len);


int r3_tree_compile(node *n, char** errstr);

int r3_tree_compile_patterns(node * n, char** errstr);

node * r3_tree_matchl(const node * n, const char * path, int path_len, match_entry * entry);

bool r3_node_has_slug_edges(const node *n);

edge * r3_edge_createl(const char * pattern, int pattern_len, node * child);

node * r3_edge_branch(edge *e, int dl);

void r3_edge_free(edge * edge);





route * r3_route_create(const char * path);

route * r3_route_createl(const char * path, int path_len);


void r3_node_append_route(node * n, route * route);

void r3_route_free(route * route);

int r3_route_cmp(const route *r1, const match_entry *r2);

route * r3_tree_match_route(const node *n, match_entry * entry);


int r3_pattern_to_opcode(const char * pattern, int pattern_len);


match_entry * match_entry_createl(const char * path, int path_len);

void match_entry_free(match_entry * entry);
]]



local _M = { _VERSION = '0.01' }
local mt = { __index = _M }

local bit = require "bit"
local _METHOD_GET     = 2;
local _METHOD_POST    = bit.lshift(2,1);
local _METHOD_PUT     = bit.lshift(2,2);
local _METHOD_DELETE  = bit.lshift(2,3);
local _METHOD_PATCH   = bit.lshift(2,4);
local _METHOD_HEAD    = bit.lshift(2,5);
local _METHOD_OPTIONS = bit.lshift(2,6);
local _METHODS = {
  GET     = _METHOD_GET,
  POST    = _METHOD_POST,
  PUT     = _METHOD_PUT,
  DELETE  = _METHOD_DELETE,
  PATCH   = _METHOD_PATCH,
  HEAD    = _METHOD_HEAD,
  OPTIONS = _METHOD_OPTIONS,
}

----------------------------------------------------------------
-- new
----------------------------------------------------------------
function _M.new(routes)
    local self = setmetatable({
      tree = r3.r3_tree_create(10),
      match_data_index = 0,
      match_data = {},
    }, mt)

    if not routes then return self end

    -- register routes
    for i, route in ipairs(routes) do
      local method = route[1]
      local bit_methods = nil
      if type(method) ~= "table" then
        bit_methods = _METHODS[method]
      else
        local methods = {}
        for i2, m in ipairs(method) do
          table_insert(methods, _METHODS[m])
        end
        bit_methods = bit.bor(unpack(methods))
      end
      local path    = route[2]
      local handler = route[3]
      -- register
      self:insert_route(bit_methods, path, handler)
    end

    -- compile
    if self.match_data_index > 0 then
      self:compile()
    end

    return self
end

function _M.compile(self)
    return r3.r3_tree_compile(self.tree, nil)
end

function _M.dump(self, level)
    level = level or 0
    return r3.r3_tree_dump(self.tree, level)
end

function _M.tree_free(self)
    return r3.r3_tree_free(self.tree)
end

function _M.match_entry_free(self, entry)
    return r3.match_entry_free(entry)
end

function _M.insert_route(self, method, path, block)
    if not method or not path or not block then return end

    self.match_data_index = self.match_data_index + 1
    self.match_data[self.match_data_index] = block
    local dataptr = ffi_cast('void *', ffi_cast('intptr_t', self.match_data_index))

    -- route * r3_tree_insert_routel_ex(node *tree, int method, const char *path, int path_len, void *data, char **errstr);
    r3.r3_tree_insert_routel_ex(self.tree, method, path, string_len(path), dataptr, nil)
end

function _M.match_route(self, method, route, ...)
    local block
    local stokens={}

    local entry = r3.match_entry_createl(route, string_len(route))
    entry.request_method = method;
    node = r3.r3_tree_match_route(self.tree, entry)
    if node == nil then
      self:match_entry_free(entry);
      entry = nil
      return false
    end

    -- get match data from index
    local i = tonumber(ffi_cast('intptr_t', ffi_cast('void *', node.data)))
    block = self.match_data[i]

    -- token proc
    if entry ~= nil and entry.vars and entry.vars.len then
      for i=0, entry.vars.len-1 do
        local token = ffi_string(entry.vars.tokens[i])
        table_insert(stokens, token)
      end
    end

    -- free
    self:match_entry_free(entry);
    entry = nil

    -- execute block
    block(stokens, ...)
    return true
end

----------------------------------------------------------------
-- method
----------------------------------------------------------------
function _M.get(self, path, block)
  self:insert_route(_METHODS["GET"], path, block)
end
function _M.post(self, path, block)
  self:insert_route(_METHODS["POST"], path, block)
end
function _M.put(self, path, block)
  self:insert_route(_METHODS["PUT"], path, block)
end
function _M.delete(self, path, block)
  self:insert_route(_METHODS["DELETE"], path, block)
end

----------------------------------------------------------------
-- dispatcher
----------------------------------------------------------------
function _M.dispatch(self, method, path, ...)
  return self:match_route(_METHODS[method], path, ...)
end
function _M.dispatch_ngx(self)
  local method = string_upper(ngx.var.request_method)
  local path = ngx.var.uri
  local params = {}
  local body = ""
  if method == "GET" then
    params = ngx.req.get_uri_args()
  elseif method == "POST" then
    ngx.req.read_body()
    params = ngx.req.get_post_args()
  else
    ngx.req.read_body()
    body = ngx.req.get_body_data()
  end
  return self:match_route(_METHODS[method], path, params, body)
end

return _M
