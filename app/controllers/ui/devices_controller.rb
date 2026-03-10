class Ui::DevicesController < Ui::BaseController
  def index
    node = Node.instance
    user = node&.user
    @node_device     = node&.device
    @own_devices     = user&.devices&.includes(:connections, :apps) || []
    @contact_devices = user&.contacts&.includes(devices: [ :connections, :apps ])
                           &.flat_map(&:devices) || []
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
