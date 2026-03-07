class Ui::BaseController < ApplicationController
  before_action :require_localhost!

  private

  def require_localhost!
    unless request.local?
      render plain: "Forbidden: UI is only accessible from localhost", status: :forbidden
    end
  end
end
