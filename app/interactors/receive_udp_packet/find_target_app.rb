class ReceiveUdpPacket::FindTargetApp
  include Interactor

  # context requires: raw_packet
  # context sets: target_app

  def call
    app_uuid = context.raw_packet["target_app_uuid"]
    app = App.accepted.find_by(app_uuid: app_uuid)
    context.fail!(message: "Target app not found or not accepted: #{app_uuid}") unless app

    context.target_app = app
  end
end
