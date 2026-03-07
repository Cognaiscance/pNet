class Contact < ApplicationRecord
  belongs_to :owner, class_name: "User"
  belongs_to :contact_user, class_name: "User", foreign_key: :contact_id

  validates :owner_id, uniqueness: { scope: :contact_id }
  validates :contact_id, presence: true
  validate :not_self_contact

  private

  def not_self_contact
    errors.add(:contact_id, "cannot be the same as owner") if owner_id == contact_id
  end
end
