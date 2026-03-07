class ReceiveUdpPacket::DecryptPayload
  include Interactor

  # context requires: raw_packet, sender_connection
  # context sets: decrypted_payload

  def call
    packet = context.raw_packet
    connection = context.sender_connection
    eke = connection.active_ephemeral_key_exchange

    box = if eke&.complete? && !eke.expired?
      eke.shared_secret
    else
      connection.static_shared_secret(Node.instance&.user)
    end

    context.fail!(message: "No shared secret available for this connection") unless box
    nonce = Base64.strict_decode64(packet["nonce"])
    ciphertext = Base64.strict_decode64(packet["payload"])

    plaintext = box.open(nonce, ciphertext)
    context.decrypted_payload = JSON.parse(plaintext)
  rescue RbNaCl::CryptoError => e
    context.fail!(message: "Decryption failed: #{e.message}")
  end
end
