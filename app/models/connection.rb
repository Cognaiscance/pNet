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
end
