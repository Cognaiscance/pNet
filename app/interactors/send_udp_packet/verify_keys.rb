class SendUdpPacket::VerifyKeys
  include Interactor

  # context requires: destination_connection
  # context sets: ephemeral_key_exchange (if fresh)

  def call
    connection = context.destination_connection
    eke = connection.active_ephemeral_key_exchange

    if eke&.complete? && !eke.expired?
      context.ephemeral_key_exchange = eke
    else
      context.needs_new_ephemeral_keys = true
    end
  end
end
