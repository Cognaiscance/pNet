require "base64"
require "json"
require "socket"

class Ui::SetupController < Ui::BaseController
  skip_before_action :require_localhost!

  def new
    redirect_to ui_dashboard_path if Node.instance.present?
  end

  def create
    pairing_data = parse_pairing_code(params[:pairing_code])

    ActiveRecord::Base.transaction do
      user = if pairing_data
        u = User.find_or_initialize_by(uuid: pairing_data["user_uuid"])
        u.alias = pairing_data["user_alias"]
        u.save!
        u
      else
        User.create!(alias: params[:user_alias])
      end

      device = Device.create!(alias: params[:device_alias], user: user)
      key_pair = KeyPair.generate_for(device)
      Node.create!(user: user, device: device)

      if pairing_data
        register_existing_device(pairing_data, user)
        send_device_pairing_packet(pairing_data, device, key_pair)
      end
    end

    redirect_to ui_dashboard_path, notice: "Node configured successfully!"
  rescue => e
    flash.now[:alert] = "Setup failed: #{e.message}"
    render :new, status: :unprocessable_entity
  end

  private

  def parse_pairing_code(code)
    return nil if code.blank?
    data = JSON.parse(Base64.urlsafe_decode64(code.strip))
    return nil unless data["type"] == "device_pairing" && data["v"] == 1
    return nil if Time.parse(data["expires_at"]) < Time.current
    data
  rescue
    nil
  end

  def register_existing_device(pairing_data, user)
    existing = Device.find_or_initialize_by(uuid: pairing_data["device_uuid"])
    existing.alias = pairing_data["device_alias"]
    existing.user  = user
    existing.save!
    existing.connections.create!(
      host_name:       "#{pairing_data["host"]}:#{pairing_data["port"]}",
      protocol:        "udp",
      peer_public_key: pairing_data["public_key"]
    )
  end

  def send_device_pairing_packet(pairing_data, new_device, key_pair)
    host = ENV.fetch("PNET_HOST", nil)
    return unless host

    packet = {
      type:         "device_pairing",
      user_uuid:    new_device.user.uuid,
      user_alias:   new_device.user.alias,
      device_uuid:  new_device.uuid,
      device_alias: new_device.alias,
      host:         host,
      port:         ENV.fetch("PNET_UDP_PORT", 7777).to_i,
      public_key:   key_pair.public_key
    }.to_json

    socket = UDPSocket.new
    socket.send(packet, 0, pairing_data["host"], pairing_data["port"].to_i)
    socket.close
  rescue => e
    Rails.logger.warn("SetupController: failed to send device pairing packet: #{e.message}")
  end
end
