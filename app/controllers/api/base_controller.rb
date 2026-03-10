class Api::BaseController < ActionController::API
  before_action :authenticate_app!

  private

  def authenticate_app!
    token = request.headers["Authorization"]&.delete_prefix("Bearer ")
    digest = token.present? ? Digest::SHA256.hexdigest(token) : nil
    app = digest ? App.find_by(api_key_digest: digest) : nil

    if app.nil?
      render json: { error: "Unauthorized" }, status: :unauthorized
    elsif app.rejected?
      render json: { error: "Access denied — this app has been blocked" }, status: :forbidden
    else
      @current_app = app
    end
  end
end
