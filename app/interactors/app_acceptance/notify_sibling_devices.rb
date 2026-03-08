require "socket"
require "json"

class AppAcceptance::NotifySiblingDevices
  include Interactor

  # context requires: app

  def call
    node = Node.instance
    return unless node&.user && node&.device

    local_user   = node.user
    local_device = node.device

    sibling_devices = local_user.devices.where.not(id: local_device.id)
    return if sibling_devices.empty?

    apps_data = local_device.apps.accepted.map { |a| { app_uuid: a.app_uuid, app_name: a.app_name } }
    packet = {
      type:               "app_sync",
      sender_user_uuid:   local_user.uuid,
      sender_device_uuid: local_device.uuid,
      apps:               apps_data
    }.to_json

    socket = UDPSocket.new
    sibling_devices.each do |device|
      conn = device.active_connection
      next unless conn
      host, port = conn.host_name.split(":")
      socket.send(packet, 0, host, port.to_i)
    end
  rescue => e
    Rails.logger.warn("AppAcceptance::NotifySiblingDevices: #{e.message}")
  ensure
    socket&.close
  end
end
