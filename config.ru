require './lib/srv'
require 'rubygems'
require 'bundler'
Bundler.require(ENV['RACK_ENV'])

unless (User.find_by_name("admin"))
        puts "-- Generating admin user"
        User.generate("admin")
end


if (ENV['RACK_ENV'] == 'production')
        myCA = CA.new()
	map('/') { run MyServer.new }
else
        myCA = CA.new()
        srvCerts = {}
        srvCerts[:cert], srvCerts[:key] = myCA.ServerKeypair()

        webrick_options = {
                :Port               => 8443,
                :Logger             => WEBrick::Log::new($stderr, WEBrick::Log::DEBUG),
                :DocumentRoot       => "/ruby/htdocs",
                :SSLEnable          => true,
                :SSLVerifyClient    => OpenSSL::SSL::VERIFY_PEER,
                :SSLCACertificateFile   => myCA.CertFile,
                :SSLCertificate     => srvCerts[:cert],
                :SSLPrivateKey      => srvCerts[:key],        
        }

        server = WEBrick::HTTPServer.new(webrick_options)
        server.mount "/", Rack::Handler::WEBrick, MyServer.new
        Signal.trap(:INT) { server.shutdown }
        server.start
end

