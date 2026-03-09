class SendUdpPacket::SendPacket
  include Interactor

  # context requires: destination_connection, encrypted_payload, nonce,
  #                   from_app, destination_user, destination_device

  def call
    connection = context.destination_connection
    node = Node.instance

    message_id = SecureRandom.uuid
    packet = {
      sender_user_uuid:   node&.user&.uuid,
      sender_device_uuid: node&.device&.uuid,
      target_app_uuid:    context.to_app_uuid,
      nonce:              context.nonce,
      payload:            context.encrypted_payload,
      message_id:         message_id,
      reply_port:         ENV.fetch("PNET_UDP_PORT", 7777).to_i
    }.to_json

    host, port = connection.host_name.split(":")
    socket = UDPSocket.new
    socket.send(packet, 0, host, port.to_i)
    socket.close

    OutboundMessage.register(message_id: message_id, packet_json: packet, host: host, port: port.to_i)

    context.sent_at = Time.current
  end
end
