class EphemeralKeyExchange < ApplicationRecord
  belongs_to :connection
  has_one :key_pair, as: :owner, dependent: :destroy

  validates :connection, presence: true

  def expired?
    timeout.present? && timeout < Time.current
  end

  def complete?
    peer_public_key.present? && key_pair.present?
  end

  def shared_secret
    return nil unless complete?

    local_private = RbNaCl::PrivateKey.new(key_pair.private_key_bytes)
    peer_public = RbNaCl::PublicKey.new(Base64.strict_decode64(peer_public_key))
    RbNaCl::Box.new(peer_public, local_private)
  end
end
