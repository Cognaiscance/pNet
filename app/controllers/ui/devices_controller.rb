class Ui::DevicesController < Ui::BaseController
  def index
    user = Node.instance&.user
    @devices = user&.devices&.includes(:connections) || []
  end
end
