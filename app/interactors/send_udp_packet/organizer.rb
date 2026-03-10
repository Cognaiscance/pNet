class SendUdpPacket::Organizer
  include Interactor::Organizer

  organize SendUdpPacket::FindDestination,
           SendUdpPacket::VerifyKeys,
           SendUdpPacket::RequestEphemeralKeys,
           SendUdpPacket::EncryptPayload,
           SendUdpPacket::SendPacket
end
