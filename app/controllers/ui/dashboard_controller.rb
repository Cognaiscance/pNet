class Ui::DashboardController < Ui::BaseController
  def index
    @node = Node.instance
    @pending_key_exchanges = EphemeralKeyExchange
      .where(peer_public_key: nil)
      .where("timeout IS NULL OR timeout > ?", Time.current)
      .includes(connection: :connectable)
      .order(created_at: :asc)
  end
end
