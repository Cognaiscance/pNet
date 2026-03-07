class User < ApplicationRecord
  has_many :key_pairs, as: :owner, dependent: :destroy
  has_many :devices, dependent: :destroy
  has_many :contact_links, class_name: "Contact", foreign_key: :owner_id, dependent: :destroy
  has_many :contacts, through: :contact_links, source: :contact_user

  validates :uuid, presence: true, uniqueness: true
  validates :alias, presence: true

  before_validation :generate_uuid, on: :create

  def active_key_pair
    key_pairs.order(created_at: :desc).first
  end

  private

  def generate_uuid
    self.uuid ||= SecureRandom.uuid
  end
end
