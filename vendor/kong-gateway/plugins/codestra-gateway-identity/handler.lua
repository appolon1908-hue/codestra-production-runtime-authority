local GatewayIdentity = { PRIORITY = 850, VERSION = "1.0.0" }

function GatewayIdentity:access(conf)
  local file = io.open(conf.secret_file, "r")
  if not file then
    return kong.response.exit(503, { error = "gateway_identity_unavailable" })
  end
  local secret = file:read("*a") or ""
  file:close()
  secret = secret:gsub("%s+$", "")
  if secret == "" then
    return kong.response.exit(503, { error = "gateway_identity_unavailable" })
  end
  kong.service.request.set_header("X-Codestra-Gateway-Secret", secret)
end

return GatewayIdentity
