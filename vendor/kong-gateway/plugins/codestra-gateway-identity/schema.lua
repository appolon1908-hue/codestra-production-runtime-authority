local typedefs = require "kong.db.schema.typedefs"

return {
  name = "codestra-gateway-identity",
  fields = {
    { protocols = typedefs.protocols_http },
    { config = {
        type = "record",
        fields = {
          { secret_file = { type = "string", required = true, default = "/run/secrets/control_plane_gateway_secret" } },
        },
      },
    },
  },
}
