class SendUdpPacket::FindDestination
  include Interactor

  # context requires: to_user_uuid, to_device_uuid, from_app
  # context sets: destination_user, destination_device, destination_connection

  def call
    user = User.find_by(uuid: context.to_user_uuid)
    context.fail!(message: "Destination user not found") unless user

    device = user.devices.find_by(uuid: context.to_device_uuid)
    context.fail!(message: "Destination device not found") unless device

    connection = device.active_connection
    context.fail!(message: "No active connection for destination device") unless connection

    context.destination_user = user
    context.destination_device = device
    context.destination_connection = connection
  end
end
