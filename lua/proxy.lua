-- ════════════════════════════════════════════════════════════════
-- LitePipe — Transparent URL-rewriting proxy module
-- v4 — Base64-encoded target URLs (fixes nginx // collapse)
-- ════════════════════════════════════════════════════════════════

local M = {}

-- ───────────────────────────────────────────────────────────────
-- Base64 URL-safe encode/decode
-- Glype/CroxyProxy pattern: encode target URL to avoid // in path
-- ───────────────────────────────────────────────────────────────
local function b64_encode(str)
    local b = ngx.encode_base64(str)
    -- URL-safe: + → -, / → _, strip =
    b = b:gsub("+", "-"):gsub("/", "_"):gsub("=+$", "")
    return b
end

local function b64_decode(str)
    -- Restore standard base64: - → +, _ → /
    local b = str:gsub("-", "+"):gsub("_", "/")
    -- Re-add padding
    local pad = (4 - #b % 4) % 4
    b = b .. string.rep("=", pad)
    return ngx.decode_base64(b)
end

-- ───────────────────────────────────────────────────────────────
-- RFC 3986 Path Resolver
-- ───────────────────────────────────────────────────────────────
local function resolve_path(base_path, rel_url)
    if rel_url:match("^/") then return rel_url end

    local segments = {}
    for seg in base_path:gmatch("[^/]+") do
        table.insert(segments, seg)
    end

    if not base_path:match("/$") then
        table.remove(segments)
    end

    for seg in rel_url:gmatch("[^/]+") do
        if seg == "." then
            -- skip
        elseif seg == ".." then
            table.remove(segments)
        else
            table.insert(segments, seg)
        end
    end

    return "/" .. table.concat(segments, "/")
end

-- ───────────────────────────────────────────────────────────────
-- PROXY URL — convert any URL to /browse/b64:... form
-- ───────────────────────────────────────────────────────────────
local function proxy_url(url, dest_host, dest_proto, page_path)
    if not url or url == "" then return url end
    if url:match("^/browse/") then return url end

    local full_url

    if url:match("^https?://") then
        full_url = url
    elseif url:match("^//") then
        full_url = dest_proto .. ":" .. url
    elseif url:match("^/") then
        full_url = dest_proto .. "://" .. dest_host .. url
    elseif page_path and page_path ~= "/" then
        local resolved = resolve_path(page_path, url)
        full_url = dest_proto .. "://" .. dest_host .. resolved
    else
        full_url = dest_proto .. "://" .. dest_host .. "/" .. url
    end

    return "/browse/b64:" .. b64_encode(full_url)
end

-- ───────────────────────────────────────────────────────────────
-- ACCESS PHASE — parse target URL from request path
-- ───────────────────────────────────────────────────────────────
function M.access()
    local req_uri = ngx.var.request_uri
    local path_part = req_uri:match("^/browse/(.+)$")

    if not path_part then
        ngx.exit(ngx.HTTP_NOT_FOUND)
        return
    end

    -- Strip query string if present
    local target
    if path_part:match("^b64:") then
        -- Base64-encoded URL (new format)
        local b64 = path_part:match("^b64:([^?]+)")
        if not b64 then
            ngx.exit(ngx.HTTP_BAD_REQUEST)
            return
        end
        target = b64_decode(b64)
        if not target then
            ngx.exit(ngx.HTTP_BAD_REQUEST)
            return
        end
        -- Re-attach query string if present in original request
        local qs = path_part:match("b64:[^?]+%?(.+)$")
        if qs then
            target = target .. "?" .. qs
        end
    else
        -- Legacy raw URL format (for backward compat)
        target = path_part
        -- Remove query string for parsing, re-add later
    end

    local protocol, hostport = target:match("^(https?)://([^/]+)")
    if not hostport then
        ngx.exit(ngx.HTTP_BAD_REQUEST)
        return
    end

    local hostname = hostport:match("^([^:]+)") or hostport

    local page_path = target:match("^https?://[^/]+([^?]*)") or "/"
    if page_path == "" then page_path = "/" end

    ngx.ctx.target_url = target
    ngx.ctx.dest_host = hostport
    ngx.ctx.dest_hostname = hostname
    ngx.ctx.dest_protocol = protocol or "https"
    ngx.ctx.page_path = page_path

    ngx.var.target_url = target
    ngx.var.dest_host = hostport
end

-- ───────────────────────────────────────────────────────────────
-- HEADER FILTER — rewrite response headers for proxy transparency
-- ───────────────────────────────────────────────────────────────
function M.header_filter()
    local dest_host  = ngx.ctx.dest_host or ngx.var.dest_host or ""
    local dest_proto = ngx.ctx.dest_protocol or "https"

    -- Rewrite Location header (3xx redirects)
    local loc = ngx.header["Location"]
    if loc then
        if loc:match("^https?://") then
            ngx.header["Location"] = "/browse/b64:" .. b64_encode(loc)
        elseif loc:match("^/") then
            local full = dest_proto .. "://" .. dest_host .. loc
            ngx.header["Location"] = "/browse/b64:" .. b64_encode(full)
        elseif loc:match("^%./") then
            local full = dest_proto .. "://" .. dest_host .. "/" .. loc:sub(3)
            ngx.header["Location"] = "/browse/b64:" .. b64_encode(full)
        end
    end

    -- Rewrite Set-Cookie — strip domain so cookies become host-only
    local cookies = ngx.header["Set-Cookie"]
    if cookies then
        if type(cookies) == "string" then
            cookies = { cookies }
        end
        for i, cookie in ipairs(cookies) do
            cookie = cookie:gsub("; *[Dd]omain=[^;]+", "")
            cookie = cookie:gsub("; *[Ss]ame[Ss]ite=[^;]+", "")
            cookies[i] = cookie
        end
        ngx.header["Set-Cookie"] = cookies
    end

    -- Strip headers that break proxied browsing
    ngx.header["Content-Security-Policy"]             = nil
    ngx.header["Content-Security-Policy-Report-Only"] = nil
    ngx.header["Strict-Transport-Security"]           = nil
    ngx.header["X-Frame-Options"]                     = nil
    ngx.header["X-Content-Type-Options"]              = nil
    ngx.header["Cross-Origin-Opener-Policy"]          = nil
    ngx.header["Cross-Origin-Embedder-Policy"]        = nil
    ngx.header["Cross-Origin-Resource-Policy"]        = nil
    ngx.header["Permissions-Policy"]                  = nil

    -- Strip Content-Length for HTML/CSS — body_filter rewrites and changes size
    local ct = ngx.var.content_type or ""
    if ct:match("text/html") or ct:match("application/xhtml") or ct:match("text/css") then
        ngx.header["Content-Length"] = nil
        ngx.header["Transfer-Encoding"] = "chunked"
    end
end

-- ───────────────────────────────────────────────────────────────
-- JS INTERCEPTOR — injected into HTML <head>
-- Uses btoa() for base64 encoding in browser
-- ───────────────────────────────────────────────────────────────
local function build_interceptor(dest_host, dest_proto, page_path)
    return string.format(
[[
<script>
(function(){
"use strict";
var H="%s",PR="%s",PP="%s";

function b64(s){
return btoa(s).replace(/\+/g,"-").replace(/\//g,"_").replace(/=+$/,"");
}

function resolvePath(base,rel){
var segs=base.split("/").filter(function(s){return s.length>0;});
if(base.charAt(base.length-1)!=="/")segs.pop();
var parts=rel.split("/");
for(var i=0;i<parts.length;i++){
if(parts[i]===".")continue;
else if(parts[i]==="..")segs.pop();
else segs.push(parts[i]);
}
return "/"+segs.join("/");
}

function pu(u){
if(!u)return u;
if(typeof u!=="string")return u;
if(u.indexOf("data:")===0||u.indexOf("blob:")===0||u.indexOf("javascript:")===0||u.indexOf("chrome-extension:")===0||u.indexOf("about:")===0||u.indexOf("mailto:")===0||u.indexOf("tel:")===0)return u;
if(u.indexOf("/browse/")===0)return u;
var full;
if(u.indexOf("http://")===0||u.indexOf("https://")===0)full=u;
else if(u.indexOf("//")===0)full=PR+":"+u;
else if(u.indexOf("/")===0)full=PR+"://"+H+u;
else if(PP)full=PR+"://"+H+resolvePath(PP,u);
else return u;
return "/browse/b64:"+b64(full);
}
window.__dsProxy=pu;

// fetch()
var F=window.fetch;
if(F){
window.fetch=function(input,init){
if(typeof input==="string")input=pu(input);
else if(input&&input instanceof Request){
try{input=new Request(pu(input.url),input);}catch(e){}
}
return F.call(this,input,init);
};
}

// XMLHttpRequest
var XO=XMLHttpRequest.prototype.open;
XMLHttpRequest.prototype.open=function(method,url){
if(typeof url==="string")url=pu(url);
return XO.apply(this,arguments);
};

// createElement — intercept src/href assignment
var CE=document.createElement;
document.createElement=function(tag){
var el=CE.call(document,tag);
var tl=tag.toLowerCase();
if(tl==="script"||tl==="img"||tl==="link"||tl==="iframe"||tl==="audio"||tl==="video"||tl==="source"||tl==="track"||tl==="input"||tl==="form"||tl==="embed"||tl==="object"){
var SA=el.setAttribute;
el.setAttribute=function(name,val){
if(name==="src"||name==="href"||name==="data-src"||name==="poster"||name==="action"||name==="data-srcset"||name==="formaction")val=pu(val);
return SA.call(this,name,val);
};
if(tl==="img"||tl==="source"){
Object.defineProperty(el,"src",{set:function(v){el.setAttribute("src",pu(v));},get:function(){return el.getAttribute("src")||"";},configurable:true});
}
}
return el;
};

// MutationObserver for dynamically inserted content
var MO=window.MutationObserver;
if(MO){
function patchEl(el){
if(!el||el.nodeType!==1)return;
var attrs=["src","href","data-src","poster","action","data-srcset","formaction"];
for(var ai=0;ai<attrs.length;ai++){
var v=el.getAttribute(attrs[ai]);
if(v&&v.indexOf("/browse/")!==0){
var pv=pu(v);
if(pv!==v)el.setAttribute(attrs[ai],pv);
}
}
if(el.querySelectorAll){
var kids=el.querySelectorAll("[src],[href],[data-src],[poster],[action],[data-srcset],[formaction]");
for(var ki=0;ki<kids.length;ki++){
for(var ai2=0;ai2<attrs.length;ai2++){
var kv=kids[ki].getAttribute(attrs[ai2]);
if(kv&&kv.indexOf("/browse/")!==0){
var kpv=pu(kv);
if(kpv!==kv)kids[ki].setAttribute(attrs[ai2],kpv);
}
}
}
}
}
var obs=new MO(function(muts){
for(var mi=0;mi<muts.length;mi++){
var added=muts[mi].addedNodes;
for(var ni=0;ni<added.length;ni++){
if(added[ni].nodeType===1)patchEl(added[ni]);
}
}
});
if(document.documentElement){
obs.observe(document.documentElement,{childList:true,subtree:true});
}
}

// location.assign / location.replace
try{
var LA=location.assign.bind(location);
location.assign=function(u){LA(pu(u));};
var LR=location.replace.bind(location);
location.replace=function(u){LR(pu(u));};
}catch(e){}

// window.open
var WO=window.open;
if(WO){
window.open=function(u){if(typeof u==="string")arguments[0]=pu(u);return WO.apply(window,arguments);};
}

// EventSource (SSE)
if(window.EventSource){
var OES=EventSource;
window.EventSource=function(url,c){return new OES(pu(url),c);};
EventSource.prototype=OES.prototype;
}

// History pushState/replaceState
try{
var HP=history.pushState;
history.pushState=function(st,title,url){if(url&&typeof url==="string")arguments[2]=pu(url);return HP.apply(this,arguments);};
var HR=history.replaceState;
history.replaceState=function(st,title,url){if(url&&typeof url==="string")arguments[2]=pu(url);return HR.apply(this,arguments);};
}catch(e){}

// <a> click interceptor
document.addEventListener("click",function(e){
var a=e.target.closest?e.target.closest("a"):null;
if(a&&a.href){
var oh=a.getAttribute("href");
if(oh&&oh.indexOf("/browse/")!==0){
a.setAttribute("href",pu(oh));
}
}
},true);

})();
</script>
]], dest_host, dest_proto, page_path)
end

-- ───────────────────────────────────────────────────────────────
-- HTML REWRITER
-- ───────────────────────────────────────────────────────────────
local function rewrite_html(body, dest_host, dest_proto, page_path)
    local pu = function(url)
        return proxy_url(url, dest_host, dest_proto, page_path)
    end

    -- Remove <base> tags
    body = body:gsub("<base[^>]*>", "")

    -- HTML attributes
    local attrs = {
        "href", "src", "action", "poster",
        "data%-src", "data%-href", "data%-url", "data%-original",
        "data%-lazy%-src", "data%-bg", "data%-poster", "data%-image",
        "data%-thumb", "data%-srcset", "formaction",
    }

    for _, attr in ipairs(attrs) do
        body = body:gsub(attr .. '="(https?://[^"]+)"',
            function(u) return attr .. '="' .. pu(u) .. '"' end)
        body = body:gsub(attr .. "='(https?://[^']+)'",
            function(u) return attr .. "='" .. pu(u) .. "'" end)
        body = body:gsub(attr .. '="(//[^"]+)"',
            function(u) return attr .. '="' .. pu(u) .. '"' end)
        body = body:gsub(attr .. "='(//[^']+)'",
            function(u) return attr .. "='" .. pu(u) .. "'" end)
        body = body:gsub(attr .. '="(/[^"]*)"',
            function(u) return attr .. '="' .. pu(u) .. '"' end)
        body = body:gsub(attr .. "='(/[^']*)'",
            function(u) return attr .. "='" .. pu(u) .. "'" end)
    end

    -- CSS url() in inline styles and <style> blocks
    body = body:gsub("url%((https?://[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%((//[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%((/[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%(['\"](https?://[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)
    body = body:gsub("url%(['\"](//[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)
    body = body:gsub("url%(['\"](/[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)

    -- srcset (comma-separated URL + descriptor pairs)
    body = body:gsub('srcset="([^"]+)"', function(s)
        local parts = {}
        for entry in s:gmatch("[^,]+") do
            entry = entry:gsub("^%s+", ""):gsub("%s+$", "")
            local url, desc = entry:match("^(%S+)%s*(.*)$")
            if url then
                local proxied = pu(url)
                if desc and desc ~= "" then
                    table.insert(parts, proxied .. " " .. desc)
                else
                    table.insert(parts, proxied)
                end
            end
        end
        return 'srcset="' .. table.concat(parts, ", ") .. '"'
    end)

    -- Meta refresh redirects
    body = body:gsub(
        '(http%-equiv=["\']refresh["\']%s+content=["\'][^"\']*?url=)(https?://[^"\']+)',
        function(prefix, url) return prefix .. pu(url) end)
    body = body:gsub(
        '(http%-equiv=["\']refresh["\']%s+content=["\'][^"\']*?url=)(/[^"\']+)',
        function(prefix, url) return prefix .. pu(url) end)

    -- Inject JS interceptor
    local interceptor = build_interceptor(dest_host, dest_proto, page_path)
    if body:find("</head>", 1, true) then
        body = body:gsub("</head>", interceptor .. "</head>", 1)
    elseif body:find("<head[^>]*>", 1) then
        body = body:gsub("(<head[^>]*>)", "%1" .. interceptor, 1)
    elseif body:find("<html", 1) then
        body = body:gsub("(<html[^>]*>)", "%1" .. interceptor, 1)
    elseif body:find("<body", 1) then
        body = body:gsub("(<body[^>]*>)", "%1" .. interceptor, 1)
    else
        body = interceptor .. body
    end

    return body
end

-- ───────────────────────────────────────────────────────────────
-- CSS REWRITER
-- ───────────────────────────────────────────────────────────────
local function rewrite_css(body, dest_host, dest_proto, page_path)
    local pu = function(url)
        return proxy_url(url, dest_host, dest_proto, page_path)
    end

    body = body:gsub("url%((https?://[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%((//[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%((/[^)]+)%)",
        function(u) return "url(" .. pu(u) .. ")" end)
    body = body:gsub("url%(['\"](https?://[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)
    body = body:gsub("url%(['\"](//[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)
    body = body:gsub("url%(['\"](/[^)'\"]+)['\"]%)",
        function(u) return "url('" .. pu(u) .. "')" end)

    body = body:gsub('@import%s+["\'](https?://[^"\']+)["\']',
        function(u) return '@import "' .. pu(u) .. '"' end)
    body = body:gsub('@import%s+["\'](/[^"\']+)["\']',
        function(u) return '@import "' .. pu(u) .. '"' end)
    body = body:gsub("@import%s+url%((https?://[^)]+)%)",
        function(u) return "@import url(" .. pu(u) .. ")" end)

    return body
end

-- ───────────────────────────────────────────────────────────────
-- BODY FILTER — buffer, rewrite, output
-- ───────────────────────────────────────────────────────────────
function M.body_filter()
    local ct = ngx.var.content_type or ""
    local should_process = ct:match("text/html")
                        or ct:match("application/xhtml")
                        or ct:match("text/css")

    if not should_process then
        return  -- Stream as-is (images, video, JS, binary)
    end

    if ngx.ctx.overflow then
        return
    end

    if not ngx.ctx.body_chunks then
        ngx.ctx.body_chunks = {}
        ngx.ctx.body_size = 0
    end

    local chunk = ngx.arg[1]
    local eof   = ngx.arg[2]

    if chunk then
        ngx.ctx.body_size = ngx.ctx.body_size + #chunk

        if ngx.ctx.body_size > 5242880 then
            ngx.ctx.overflow = true
            local buffered = table.concat(ngx.ctx.body_chunks)
            ngx.ctx.body_chunks = nil
            ngx.arg[1] = buffered .. chunk
            return
        end

        table.insert(ngx.ctx.body_chunks, chunk)
    end

    if not eof then
        ngx.arg[1] = nil
        return
    end

    local dest_host  = ngx.ctx.dest_host or ngx.var.dest_host or ""
    local dest_proto = ngx.ctx.dest_protocol or "https"
    local page_path  = ngx.ctx.page_path or "/"

    local body = table.concat(ngx.ctx.body_chunks or {})
    ngx.ctx.body_chunks = nil

    if #body == 0 then
        ngx.arg[1] = nil
        return
    end

    if ct:match("text/html") or ct:match("application/xhtml") then
        body = rewrite_html(body, dest_host, dest_proto, page_path)
    elseif ct:match("text/css") then
        body = rewrite_css(body, dest_host, dest_proto, page_path)
    end

    ngx.arg[1] = body
end

return M
