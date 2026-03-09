class Connection < ApplicationRecord
  belongs_to :connectable, polymorphic: true
  has_many :ephemeral_key_exchanges, dependent: :destroy

  validates :host_name, presence: true

  def self.record_address(connectable:, host_name:, peer_public_key: nil)
    conn = connectable.connections.find_by(protocol: "udp")
    if conn
      attrs = { host_name: host_name, last_seen_at: Time.current }
      attrs[:peer_public_key] = peer_public_key if peer_public_key.present?
      conn.update!(attrs)
    else
      connectable.connections.create!(
        host_name: host_name, protocol: "udp",
        peer_public_key: peer_public_key, last_seen_at: Time.current
      )
    end
  end

  def active_ephemeral_key_exchange
    ephemeral_key_exchanges.order(created_at: :desc).first
  end

  def expired?
    timeout.present? && timeout < Time.current
  end

  def static_shared_secret(local_device)
    return nil unless peer_public_key.present? && local_device&.active_key_pair

    local_private = RbNaCl::PrivateKey.new(local_device.active_key_pair.private_key_bytes)
    peer_public   = RbNaCl::PublicKey.new(Base64.strict_decode64(peer_public_key))
    RbNaCl::Box.new(peer_public, local_private)
  end
end
