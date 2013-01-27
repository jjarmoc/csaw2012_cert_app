require 'rubygems'
require 'httpclient'
require 'openssl'
require './lib/openssl-patch.rb'


#URL = "https://127.0.0.1:8443/" #set URL to wherever the app resides.
URL = "https://csaw.offenseindepth.com"
BASENAME = "Attacker"
thisname = rand(100000).to_s + BASENAME

$stdout.sync = true

http = HTTPClient.new
http.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE

my = {}
admin = {}
temp = {}

puts "-- Getting my keypair for #{thisname}"
response = http.post("#{URL}/cert/generate", {"name" => thisname})
my[:p12] = OpenSSL::PKCS12.new(response.body)
my[:n] = my[:p12].key.n
admin[:ca] = my[:p12].ca_certs

puts "-- Getting admin cert."
http.ssl_config.client_cert = my[:p12].certificate
http.ssl_config.client_key = my[:p12].key
admresponse = http.get("#{URL}/cert/get?name=admin")

admin[:crt] = OpenSSL::X509::Certificate.new(admresponse.body)
admin[:n] = admin[:crt].public_key.n

p = 0
count = 0

if (admin[:n].gcd(my[:n]) == 1)
	until (p > 1)
		printf "-- Creating keypair for #{thisname}#{count.to_s}"
		response = http.post("#{URL}/cert/generate", {"name" => thisname+ count.to_s})
		temp[:crt] = OpenSSL::PKCS12.new(response.body)
		printf " - Testing against admin..."
		temp[:n] = temp[:crt].key.n
		p = admin[:n].gcd(temp[:n])
		printf " No shared factors.\n"
		count = count + 1
	end
	printf "!! Found a shared factor for p!\n"
end

printf "-- Calculating q "
q = (admin[:n]/p)[0]
printf "- Done.\n"

printf "-- Generating key "
admin[:key] = OpenSSL::PKey::RSA.new_from_pq(p, q)
printf "- Done.\n"

printf "-- Verfiying key "
if (admin[:crt].check_private_key(admin[:key]))
	printf "- Success!\n"
else 
	printf "- FAILED.\n"
	exit
end

printf "-- Generating p12 "
admin[:p12] = OpenSSL::PKCS12.create(nil, nil, admin[:key], admin[:crt], admin[:ca])
printf "- Done\n"

printf "-- Writing to file admin.p12 "
File.open("admin.p12", 'w') {|f| f.write(admin[:p12].to_der) }
x = OpenSSL::PKCS12.new(File.read("admin.p12"))
printf "- Done\n"

printf "-- Fetching home page as admin."
http2 = HTTPClient.new
http2.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
http2.ssl_config.client_cert = admin[:p12].certificate
http2.ssl_config.client_key = admin[:p12].key
puts http2.get(URL).body
printf "-- ALL DONE!\n"
