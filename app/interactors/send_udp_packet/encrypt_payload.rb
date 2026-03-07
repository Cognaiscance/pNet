class SendUdpPacket::EncryptPayload
  include Interactor

  # context requires: ephemeral_key_exchange, payload, from_app
  # context sets: encrypted_payload, nonce

  def call
    if context.awaiting_key_exchange
      context.fail!(message: "Awaiting key exchange completion. Retry after handshake.")
    end

    box = if context.use_static_keys
      context.destination_connection.static_shared_secret(Node.instance&.user)
    else
      context.ephemeral_key_exchange&.shared_secret
    end
    context.fail!(message: "Cannot establish shared secret") unless box

    nonce = RbNaCl::Random.random_bytes(box.nonce_bytes)
    payload_json = context.payload.to_json

    context.nonce = Base64.strict_encode64(nonce)
    context.encrypted_payload = Base64.strict_encode64(box.box(nonce, payload_json))
  end
end
