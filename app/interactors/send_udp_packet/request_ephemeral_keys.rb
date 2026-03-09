class SendUdpPacket::RequestEphemeralKeys
  include Interactor

  # context requires: needs_new_ephemeral_keys, destination_connection
  # context sets: ephemeral_key_exchange

  def call
    return unless context.needs_new_ephemeral_keys

    connection = context.destination_connection

    if connection.peer_public_key.present?
      # Both sides exchanged connection codes — use static keys immediately, no round-trip needed
      context.use_static_keys = true
      return
    end

    # Generate a new ephemeral key pair for this exchange
    eke = EphemeralKeyExchange.create!(
      connection: connection,
      timeout: 24.hours.from_now
    )

    key_pair = KeyPair.generate_for(eke)

    # Send a handshake packet to the remote node to initiate key exchange
    # The remote node will respond with its public key via UDP
    message_id = SecureRandom.uuid
    handshake_packet = {
      type:               "key_exchange",
      sender_user_uuid:   Node.instance&.user&.uuid,
      sender_device_uuid: Node.instance&.device&.uuid,
      public_key:         key_pair.public_key,
      message_id:         message_id,
      reply_port:         ENV.fetch("PNET_UDP_PORT", 7777).to_i
    }

    host, port = connection.host_name.split(":")
    packet_json = handshake_packet.to_json
    socket = UDPSocket.new
    socket.send(packet_json, 0, host, port.to_i)
    socket.close

    OutboundMessage.register(message_id: message_id, packet_json: packet_json, host: host, port: port.to_i)

    context.ephemeral_key_exchange = eke
    context.awaiting_key_exchange = true
  end
end
