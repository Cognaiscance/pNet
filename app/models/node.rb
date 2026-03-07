class Node < ApplicationRecord
  belongs_to :user, optional: true
  belongs_to :device, optional: true

  before_create :enforce_singleton

  def self.instance
    first
  end

  private

  def enforce_singleton
    raise "Only one Node record is allowed" if Node.exists?
  end
end
