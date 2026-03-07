namespace :pnet do
  desc "Start the pNet UDP listener on port 7777 (or PNET_UDP_PORT env var)"
  task start: :environment do
    port = (ENV["PNET_UDP_PORT"] || 7777).to_i
    server = UdpServer.new(port: port)

    trap("INT")  { server.stop; exit }
    trap("TERM") { server.stop; exit }

    server.start
  end
end
