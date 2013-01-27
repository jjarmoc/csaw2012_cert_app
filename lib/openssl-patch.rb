require 'openssl'

module OpenSSL
	module PKey
		class RSA
			def self.new_from_pq(p = nil, q= nil, e = 65537, len = 2048)
				key = self.new()

				key.p = p ? p : OpenSSL::BN.generate_prime(len/2)
				key.q = q ? q : OpenSSL::BN.generate_prime(len/2)
				#Note that we're not checking to ensure p and q are far enough apart.
				#This is insecure against Fermat's factorization method.
				# 	See http://en.wikipedia.org/wiki/Fermat_factorization
				#Don't use this code to generate keys.

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
