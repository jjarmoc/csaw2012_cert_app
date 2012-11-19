require 'openssl'

module OpenSSL
	module PKey
		class RSA
			def self.new_from_pq(p = nil, q= nil, e = 65537, len = 2048)
				key = self.new()

				key.p = p ? p : OpenSSL::BN.generate_prime(len/2)
				key.q = q ? q : OpenSSL::BN.generate_prime(len/2)

				key.n = key.p*key.q
				key.e = e

				phi = (key.p - 1) * (key.q - 1 )
				key.d = key.e.mod_inverse(phi)

				key.dmp1 = key.d % (key.p - 1)
				key.dmq1 = key.d % (key.q - 1)
				key.iqmp = key.q.mod_inverse(key.p)
		
				return key
			end
		end
	end
end
