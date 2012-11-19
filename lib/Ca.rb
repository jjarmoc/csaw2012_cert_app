require 'openssl'
require './lib/openssl-patch'
require './lib/primes.rb'

class CA
	attr_reader :cert, :CertFile

	CA_KEY = "./keys/ca.key"
	CA_CERT = "./keys/ca.crt"
	CA_NAME = "/DC=net/DC=CSAW/CN=CSAW2012 CA"

	SERVER_KEY = "./keys/server.key"
	SERVER_CERT = "./keys/server.crt"

	KEY_LEN = 2048
	SIGN_ALG = OpenSSL::Digest::SHA256

	PRIMES = 20

	def initialize()
	@CertFile = CA_CERT

		if (File.exist?(CA_KEY) and File.exist?(CA_CERT))
	 	  @key = OpenSSL::PKey::RSA.new File.read(CA_KEY)
		  @cert = OpenSSL::X509::Certificate.new File.read(CA_CERT)
		else
		  @key = OpenSSL::PKey::RSA.new(KEY_LEN) 
		  @cert = OpenSSL::X509::Certificate.new
		  @cert.version = 2 
		  @cert.serial = 1
		  @cert.subject = OpenSSL::X509::Name.parse CA_NAME
		  @cert.issuer = @cert.subject 
		  @cert.public_key = @key.public_key
		  @cert.not_before = Time.now
		  @cert.not_after = @cert.not_before + 2 * 365 * 24 * 60 * 60 
		  ef = OpenSSL::X509::ExtensionFactory.new
		  ef.subject_certificate = @cert
		  ef.issuer_certificate = @cert
		  @cert.add_extension(ef.create_extension("basicConstraints","CA:TRUE",true))
		  @cert.add_extension(ef.create_extension("keyUsage","keyCertSign, cRLSign", true))
		  @cert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
		  @cert.add_extension(ef.create_extension("authorityKeyIdentifier","keyid:always",false))
		  @cert.sign(@key, SIGN_ALG.new)
		  
		  File.open(CA_KEY, 'w') {|f| f.write(@key) }
		  File.open(CA_CERT, 'w') {|f| f.write(@cert) }
		end
	end

	def ServerKeypair (name = "127.0.0.1")

		if (File.exist?(SERVER_KEY) and File.exist?(SERVER_CERT))
			srvkey = OpenSSL::PKey::RSA.new File.read(SERVER_KEY)
			srvcert = OpenSSL::X509::Certificate.new File.read(SERVER_CERT)
		else
			srvkey = OpenSSL::PKey::RSA.new(KEY_LEN)
			srvcert = OpenSSL::X509::Certificate.new
			srvcert.version = 2
			srvcert.serial = 1337
			srvcert.subject = OpenSSL::X509::Name.parse "/DC=net/DC=CSAW/CN=#{name}"
			srvcert.issuer = @cert.subject 
			srvcert.public_key = srvkey.public_key
			srvcert.not_before = Time.now
			srvcert.not_after = srvcert.not_before + 1 * 365 * 24 * 60 * 60
			ef = OpenSSL::X509::ExtensionFactory.new
			ef.subject_certificate = srvcert
			ef.issuer_certificate = @cert
			srvcert.add_extension(ef.create_extension("keyUsage","digitalSignature", false))
			srvcert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
			srvcert.sign(@key, SIGN_ALG.new)

			File.open(SERVER_KEY, 'w') {|f| f.write(srvkey.to_s) }
			File.open(SERVER_CERT, 'w') {|f| f.write(srvcert.to_s) }
		end
		
		return srvcert, srvkey
	end

	def genp12(name, serial, passphrase = nil, p = nil, q = nil)
		valid_to = 30 * 24 * 60 * 60 # 30 day validit

		p = OpenSSL::BN.new(Prime.new(rand(PRIMES)).value)
		newkey = OpenSSL::PKey::RSA.new_from_pq(p)

		newcert = OpenSSL::X509::Certificate.new
		newcert.version = 2 
		newcert.serial = OpenSSL::BN.new(serial)
		newcert.subject = OpenSSL::X509::Name.new [["CN", name]]
		newcert.issuer = self.cert.subject 
		newcert.public_key = newkey.public_key
		newcert.not_before = Time.now
		newcert.not_after = cert.not_before + valid_to
		ef = OpenSSL::X509::ExtensionFactory.new
		ef.subject_certificate = newcert
		ef.issuer_certificate = @cert
		newcert.add_extension(ef.create_extension("keyUsage","digitalSignature, keyEncipherment, dataEncipherment", false))
		newcert.add_extension(ef.create_extension("subjectKeyIdentifier","hash",false))
		newcert.add_extension(ef.create_extension("extendedKeyUsage","emailProtection,clientAuth", false))
		newcert.sign(@key, SIGN_ALG.new)

   		newp12 = OpenSSL::PKCS12.create(passphrase, name, newkey, newcert, [@cert])
   		return newp12
	end
end
