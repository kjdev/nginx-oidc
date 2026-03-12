local M = {}

local STUB_URL = "http://127.0.0.1:8888"
local APP_URL = "http://127.0.0.1:1984"

local function request(httpc, url, opts)
    local res, err = httpc:request_uri(url, opts)
    if not res then
        ngx.log(ngx.ERR, "Failed: ", err)
        return nil
    end
    return res
end

function M.set_state(httpc, target, state)
    httpc:request_uri(STUB_URL .. "/?action=clear_all")
    httpc:request_uri(STUB_URL .. "/?action=set&target=" .. target .. "&state=" .. state)
end

function M.clear_state(httpc)
    httpc:request_uri(STUB_URL .. "/?action=clear_all")
end

-- 3-step flow: auth -> authorize -> callback
function M.flow_to_callback(httpc)
    local res = request(httpc, APP_URL .. "/", { follow_redirects = false })
    if not res then return nil end

    local cookie = res.headers["Set-Cookie"]
    local url = res.headers["Location"]

    res = request(httpc, url, { follow_redirects = false })
    if not res then return nil end

    url = res.headers["Location"]

    return request(httpc, url, {
        follow_redirects = false,
        headers = { ["Cookie"] = cookie },
    })
end

-- 4-step flow: auth -> authorize -> callback -> redirect -> backend
function M.full_flow(httpc)
    local res = M.flow_to_callback(httpc)
    if not res then return nil end

    local url = res.headers["Location"]
    local cookie = res.headers["Set-Cookie"]

    return request(httpc, url, {
        follow_redirects = false,
        headers = { ["Cookie"] = cookie },
    })
end

return M
