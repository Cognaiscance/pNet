class InboundMessage < ApplicationRecord
  belongs_to :app

  validates :from_user_uuid, :from_device_uuid, :payload, presence: true

  scope :unread, -> { where(read_at: nil) }

  def self.mark_read(ids)
    where(id: ids).update_all(read_at: Time.current)
  end
end
