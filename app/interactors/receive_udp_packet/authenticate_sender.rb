class ReceiveUdpPacket::AuthenticateSender
  include Interactor

  # context requires: raw_packet (parsed Hash with sender_user_uuid, sender_device_uuid)
  # context sets: sender_user, sender_device, sender_connection

  def call
    packet = context.raw_packet

    user = User.find_by(uuid: packet["sender_user_uuid"])
    context.fail!(message: "Unknown sender user") unless user

    device = user.devices.find_by(uuid: packet["sender_device_uuid"])
    context.fail!(message: "Unknown sender device") unless device

    connection = device.active_connection
    context.fail!(message: "No connection for sender device") unless connection

    context.sender_user = user
    context.sender_device = device
    context.sender_connection = connection

    if context.sender_ip.present?
      port = connection.host_name.split(":").last
      Connection.record_address(connectable: device,
        host_name: "#{context.sender_ip}:#{port}")
      context.sender_connection = device.reload.active_connection
    end
  end
end
