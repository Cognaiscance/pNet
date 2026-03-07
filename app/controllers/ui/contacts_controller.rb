class Ui::ContactsController < Ui::BaseController
  def index
    @owner = Node.instance&.user
    @contacts = @owner&.contacts&.includes(:devices) || []
  end

  def create
    owner = Node.instance&.user
    contact = User.find_by(uuid: params[:contact_uuid])

    if contact.nil?
      redirect_to ui_contacts_path, alert: "User not found with that UUID."
      return
    end

    Contact.create!(owner: owner, contact_user: contact)
    redirect_to ui_contacts_path, notice: "#{contact.alias} added to contacts."
  rescue ActiveRecord::RecordInvalid => e
    redirect_to ui_contacts_path, alert: e.message
  end

  def destroy
    owner = Node.instance&.user
    contact_user = User.find(params[:id])
    owner.contact_links.find_by(contact_id: contact_user.id)&.destroy

    redirect_to ui_contacts_path, notice: "Contact removed."
  end
end
