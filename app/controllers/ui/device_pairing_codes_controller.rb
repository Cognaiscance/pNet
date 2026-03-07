require "base64"
require "json"

class Ui::DevicePairingCodesController < Ui::BaseController
  def show
    node   = Node.instance
    user   = node&.user
    device = node&.device
    port   = ENV.fetch("PNET_UDP_PORT", 7777).to_i
    host   = ENV.fetch("PNET_HOST", nil)

    key_pair = device&.active_key_pair || (device && KeyPair.generate_for(device))

    payload = {
      v:            1,
      type:         "device_pairing",
      user_uuid:    user&.uuid,
      user_alias:   user&.alias,
      device_uuid:  device&.uuid,
      device_alias: device&.alias,
      host:         host || "SET_PNET_HOST_ENV_VAR",
      port:         port,
      public_key:   key_pair&.public_key,
      expires_at:   5.minutes.from_now.utc.iso8601
    }

    @host_missing = host.nil?
    @code         = Base64.urlsafe_encode64(JSON.generate(payload))
    @expires_at   = payload[:expires_at]
  end
end
