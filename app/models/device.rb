class Device < ApplicationRecord
  belongs_to :user
  has_many :connections, as: :connectable, dependent: :destroy
  has_many :apps, dependent: :destroy

  validates :uuid, presence: true, uniqueness: true
  validates :alias, presence: true

  before_validation :generate_uuid, on: :create

  def active_connection
    connections.order(created_at: :desc).first
  end

  private

  def generate_uuid
    self.uuid ||= SecureRandom.uuid
  end
end
