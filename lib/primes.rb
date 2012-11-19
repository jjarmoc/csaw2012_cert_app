require 'openssl'
require 'mongo'
include Mongo

class Prime
	attr_reader :id, :value

	def initialize(id)
		@id = id
		@@db = Connection.new.db('CertStore').collection('Primes')
		result = @@db.find( :id => id).first
		if (result) 
			@value = result["value"]
		end

		unless (@value)
			@value = String(OpenSSL::BN.generate_prime(1024))
			@@db.insert({:id => @id, :value => @value})
		end
	end
end
