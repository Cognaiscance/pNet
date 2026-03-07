require "base64"
require "json"
require "socket"

class Ui::ConnectionCodesController < Ui::BaseController
  def show
    node = Node.instance
    user = node&.user
    device = node&.device
    port = ENV.fetch("PNET_UDP_PORT", 7777).to_i
    host = ENV.fetch("PNET_HOST", nil)

    key_pair = device&.active_key_pair || (device && KeyPair.generate_for(device))

    payload = {
      v: 1,
      user_uuid: user&.uuid,
      user_alias: user&.alias,
      device_uuid: device&.uuid,
      device_alias: device&.alias,
      host: host || "SET_PNET_HOST_ENV_VAR",
      port: port,
      public_key: key_pair&.public_key,
      expires_at: 15.minutes.from_now.utc.iso8601
    }

    @host_missing = host.nil?
    @code = Base64.urlsafe_encode64(JSON.generate(payload))
    @expires_at = payload[:expires_at]
  end

  def create
    raw = Base64.urlsafe_decode64(params[:code].to_s.strip)
    data = JSON.parse(raw)

    unless data["v"] == 1
      redirect_to ui_connection_code_path, alert: "Unsupported connection code version." and return
    end

    if Time.parse(data["expires_at"]) < Time.current
      redirect_to ui_connection_code_path, alert: "Connection code has expired." and return
    end

    local_user = Node.instance&.user

    remote_user = User.find_or_initialize_by(uuid: data["user_uuid"])
    remote_user.alias = data["user_alias"]
    remote_user.save!

    device = Device.find_or_initialize_by(uuid: data["device_uuid"])
    device.alias = data["device_alias"]
    device.user = remote_user
    device.save!

    device.connections.create!(
      host_name: "#{data["host"]}:#{data["port"]}",
      protocol: "udp",
      peer_public_key: data["public_key"]
    )

    own_device = remote_user.uuid == local_user.uuid

    unless own_device
      Contact.find_or_create_by!(owner: local_user, contact_user: remote_user)
    end

    send_peer_introduction("#{data["host"]}:#{data["port"]}")

    if own_device
      redirect_to ui_devices_path, notice: "#{device.alias} added as your device."
    else
      redirect_to ui_contacts_path, notice: "#{remote_user.alias} added as a contact."
    end
  rescue ArgumentError, JSON::ParserError
    redirect_to ui_connection_code_path, alert: "Invalid connection code."
  rescue ActiveRecord::RecordInvalid => e
    redirect_to ui_connection_code_path, alert: e.message
  end

  private

  def send_peer_introduction(remote_host_name)
    node   = Node.instance
    user   = node&.user
    device = node&.device
    host   = ENV.fetch("PNET_HOST", nil)
    return unless user && device && host

    packet = {
      type:        "peer_introduction",
      user_uuid:   user.uuid,
      user_alias:  user.alias,
      device_uuid: device.uuid,
      device_alias: device.alias,
      host:        host,
      port:        ENV.fetch("PNET_UDP_PORT", 7777).to_i,
      public_key:  device.active_key_pair&.public_key
    }.to_json

    remote_host, remote_port = remote_host_name.split(":")
    socket = UDPSocket.new
    socket.send(packet, 0, remote_host, remote_port.to_i)
    socket.close
  rescue => e
    Rails.logger.warn("ConnectionCodesController: failed to send peer introduction: #{e.message}")
  end
end
