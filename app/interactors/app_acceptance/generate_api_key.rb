class AppAcceptance::GenerateApiKey
  include Interactor

  # context requires: app
  # context sets: raw_api_key

  def call
    app = context.app
    context.fail!(message: "App not found") unless app
    context.fail!(message: "App is not pending") unless app.pending?

    raw_key = app.generate_api_key!
    app.update!(status: :accepted)

    context.raw_api_key = raw_key
  end
end
