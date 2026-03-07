class Connection < ApplicationRecord
  belongs_to :connectable, polymorphic: true
  has_many :ephemeral_key_exchanges, dependent: :destroy

  validates :host_name, presence: true

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
