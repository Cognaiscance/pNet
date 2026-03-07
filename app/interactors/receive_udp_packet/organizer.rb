class ReceiveUdpPacket::Organizer
  include Interactor::Organizer

  organize ReceiveUdpPacket::AuthenticateSender,
           ReceiveUdpPacket::DecryptPayload,
           ReceiveUdpPacket::FindTargetApp,
           ReceiveUdpPacket::ForwardToApp
end
