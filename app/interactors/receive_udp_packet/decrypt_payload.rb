class ReceiveUdpPacket::DecryptPayload
  include Interactor

  # context requires: raw_packet, sender_connection
  # context sets: decrypted_payload

  def call
    packet = context.raw_packet
    connection = context.sender_connection
    eke = connection.active_ephemeral_key_exchange

    context.fail!(message: "No ephemeral key exchange for this connection") unless eke&.complete?
    context.fail!(message: "Ephemeral keys expired") if eke.expired?

    box = eke.shared_secret
    nonce = Base64.strict_decode64(packet["nonce"])
    ciphertext = Base64.strict_decode64(packet["payload"])

    plaintext = box.open(nonce, ciphertext)
    context.decrypted_payload = JSON.parse(plaintext)
  rescue RbNaCl::CryptoError => e
    context.fail!(message: "Decryption failed: #{e.message}")
  end
end
