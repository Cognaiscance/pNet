class Ui::DashboardController < Ui::BaseController
  def index
    @node = Node.instance
    @pending_apps_count = App.pending.count
  end
end
