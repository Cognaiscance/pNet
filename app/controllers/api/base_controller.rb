class Api::BaseController < ActionController::API
  before_action :authenticate_app!

  private

  def authenticate_app!
    token = request.headers["Authorization"]&.delete_prefix("Bearer ")
    @current_app = App.accepted.find { |a| a.authenticate_api_key(token.to_s) }
    render json: { error: "Unauthorized" }, status: :unauthorized unless @current_app
  end
end
