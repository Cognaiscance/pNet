class App < ApplicationRecord
  belongs_to :device
  has_many :connections, as: :connectable, dependent: :destroy
  has_many :key_pairs, as: :owner, dependent: :destroy
  has_many :inbound_messages, dependent: :destroy

  enum :status, { pending: 0, accepted: 1, rejected: 2 }

  validates :app_uuid, presence: true, uniqueness: true
  validates :app_name, presence: true

  def active_connection
    connections.order(created_at: :desc).first
  end

  def authenticate_api_key(token)
    return false unless api_key_digest.present?
    BCrypt::Password.new(api_key_digest).is_password?(token)
  end

  def generate_api_key!
    raw_key = SecureRandom.hex(32)
    update!(api_key_digest: BCrypt::Password.create(raw_key))
    raw_key
  end
end
