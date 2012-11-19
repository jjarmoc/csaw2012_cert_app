require 'mongo'
include Mongo
require './lib/Ca.rb'

class User
	attr_reader :name, :created, :cert, :getlink, :p12, :lastaccess
	
	def initialize(name, created, cert, lastaccess, user_id)
		@name = name
		@created = created
		@cert = cert
		@lastaccess = lastaccess
		@user_id = user_id
	end

	def genkeys(pw = nil)
		@@db = Connection.new.db('CertStore').collection('Users')
		new_user = { :name => @name, :created_on => @created, :last_access => @created}
		@user_id = @@db.insert(new_user)
		@p12 = @@ca.genp12(@name, @user_id.to_s, pw)
		@cert = @p12.certificate.to_s
		@@db.update( { :_id => @user_id }, '$set' => { :pubkey => @cert} )
	end

	def accessed()
		@@db = Connection.new.db('CertStore').collection('Users')
		@@db.update( { :_id => @user_id }, '$set' => { :last_access => Time.now} )
	end

	def self.count()
		@@db = Connection.new.db('CertStore').collection('Users')
		@@db.count()
	end

	def self.generate(name = "", pw = nil)
		@@db = Connection.new.db('CertStore').collection('Users')
		@@ca = CA.new()
		user = self.new(name, Time.now, nil, nil, nil)
		user.genkeys(pw)
		return user
	end

	def self.find_by_cert(cert)
		@@db = Connection.new.db('CertStore').collection('Users')
		userhash = @@db.find( {:pubkey => cert.to_s} ).first
		
		if userhash
			user = self.new(
				userhash["name"], 
				userhash["created_on"], 
				userhash["pubkey"], 
				userhash["last_access"],
				userhash["_id"])
		else 
			user = nil
		end
		return user
	end	

	def self.find_by_name(name)
		@@db = Connection.new.db('CertStore').collection('Users')
		userhash = @@db.find( {:name => name.to_s} ).first
		if userhash
			user = self.new(
				userhash["name"], 
				userhash["created_on"], 
				userhash["pubkey"], 
				userhash["last_access"],
				userhash["_id"])
		else 
			user = nil
		end
		return user
	end

	def self.find_all(num = 10, page = 0)
		@@db = Connection.new.db('CertStore').collection('Users')
		users = []
		skip = page * num
		@@db.find().sort( [['_id', 1]]).limit(num).skip(skip).each do |row|
			users << self.new(
				row["name"], 
				row["created_on"], 
				row["pubkey"], 
				row["last_access"],
				row["_id"])
		end
		users
	end
end
