class AppRegistration::Organizer
  include Interactor::Organizer

  organize AppRegistration::ValidateRegistration,
           AppRegistration::CreateAppRecord,
           AppRegistration::NotifyPending
end
