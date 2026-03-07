class SendUdpPacket::SendPacket
  include Interactor

  # context requires: destination_connection, encrypted_payload, nonce,
  #                   from_app, destination_user, destination_device

  def call
    connection = context.destination_connection
    node = Node.instance

    packet = {
      sender_user_uuid: node&.user&.uuid,
      sender_device_uuid: node&.device&.uuid,
      target_app_uuid: context.from_app.app_uuid,
      nonce: context.nonce,
      payload: context.encrypted_payload
    }.to_json

    host, port = connection.host_name.split(":")
    socket = UDPSocket.new
    socket.send(packet, 0, host, port.to_i)
    socket.close

    context.sent_at = Time.current
  end
end
