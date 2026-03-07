class AppAcceptance::Organizer
  include Interactor::Organizer

  organize AppAcceptance::GenerateApiKey,
           AppAcceptance::DeliverApiKey
end
