class Ui::DevicesController < Ui::BaseController
  def index
    user = Node.instance&.user
    @devices = user&.devices&.includes(:connections, :apps) || []
  end

  def sync
    result = AppAcceptance::NotifySiblingDevices.call
    if result.success?
      redirect_to ui_devices_path, notice: "App sync sent to sibling devices."
    else
      redirect_to ui_devices_path, alert: "Sync failed: #{result.message}"
    end
  end
end
