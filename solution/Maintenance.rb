require 'rubygems'
require 'httpclient'
require 'mongo'
include Mongo

mins = 60
age_in_seconds = mins * 60
URL = "https://127.0.0.1:8443/"
ADMINP12 = "./admin.p12"
FLAG = "key{placeholder}"

def timestamp()
	return Time.now().to_s
end


puts "#{timestamp()} - Maintenance starting."

#Check admin cert works.
http = HTTPClient.new
http.ssl_config.verify_mode = OpenSSL::SSL::VERIFY_NONE
p12 = OpenSSL::PKCS12.new(File.read("admin.p12"))
printf "#{timestamp()} - Testing Admin Cert - "
http.ssl_config.client_cert = p12.certificate
http.ssl_config.client_key = p12.key
response = http.get(URL).body
if (response)
	printf("OK\n")
else 
	printf("FAILED!!!\n")
end

#Check flag is unchanged
printf "#{timestamp()} - Testing Flag - "
if (response.include?(FLAG))
	printf("OK\n")
else 
	printf("FAILED!!!\n")
end

#Cleanup DB
db = Connection.new.db('CertStore').collection('Users')
now = Time.now()
puts "#{timestamp()} - Cleaning up users unseen since #{now - age_in_seconds}"
db.find("last_access" => {"$lt" => (Time.now() - age_in_seconds) }).each{ |row| puts row }
db.remove("last_access" => {"$lt" => (Time.now() - age_in_seconds) })

puts "#{timestamp()} - Maintenance complete."