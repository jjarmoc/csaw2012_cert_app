require './lib/Ca.rb'
require './lib/User.rb'

require 'bundler'
Bundler.require

class MyServer  < Sinatra::Base
    set :root, File.join(File.dirname(__FILE__), "../")

	helpers do
	  include Rack::Utils
	  alias_method :h, :escape_html
	  alias_method :u, :escape

	  def require_auth
	  	if (@authenticated == false)
	  		@error = "Authentication Required"
	  		halt 401, "#{haml :error}"
	  	end
	  end
	end

	before do
		@client_cert = request.env['SSL_CLIENT_CERT'] ? request.env['SSL_CLIENT_CERT'] : nil
		@user = User.find_by_cert(@client_cert) ? User.find_by_cert(@client_cert) : nil

		if (@user == nil)
			@authenticated = false
			@user = User.new("NONE", "NONE", "NONE", "NONE", "NONE")
		end

        @user.accessed()
	end

	configure do
		mime_type :plain, 'text/plain'
	end

    get '/' do
    	if (@authenticated == false)	
     		haml :noauth
    	elsif (@user.name == "admin")
    		haml :theflag
    	else
      		haml :index 
        end
    end

    get '/about' do
    	haml :about
    end

    get '/cert/dir' do
    	require_auth()

    	count = User.count()
    	num = params[:num] ? Integer(params[:num]) : 20

    	page = params[:page] ? Integer(params[:page]) : 0
    	if (page < 0 or page > count/num) 
    		@error = "Page out of bounds."
    		halt 500, "#{haml :error}"
    	end

    	users = []
    	users = User.find_all(num, page)
    	@header = "#{page * num} to #{page * num + num} of #{count} users.\n"
    	@directory = "<div id='table'>\n"
    	users.each_with_index do |u, index|
    		if (index % 2 == 0)
				@directory << "\t<div id='row' class='odd'><a href =\"/cert/get?name=#{u u.name}\">#{h u.name}</a></div>\n"
			else
				@directory << "\t<div id='row'><a href =\"/cert/get?name=#{u u.name}\">#{h u.name}</a></div>\n"
			end
    	end
    	@directory << "</div>\n" 
    	@directory << "<div id='dirnav'>\n"
    	@directory << "<a href=\"/cert/dir?page=#{page+1}&num=#{num}\" class='next'>Next</a>" unless (page + 1 > count /num)
    	@directory << "<a href=\"/cert/dir?page=#{page-1}&num=#{num}\" class='prev'>Prev</a>" unless (page == 0)
    	@directory << "</div>\n"
    	haml :directory
    end

    post '/cert/generate' do
    	if (params[:pw] == "")
    		@error = "Please choose a password."
    		halt 500, "#{haml :error}"
    	end

    	unless (params[:pw] == params[:confpw])
    		@error = "passwords do not match."
    		halt 500, "#{haml :error}"
    	end
    	
    	if (params[:name] == nil or params[:name] == "")
    		@error = "No username specified"
    		haml :error
        elsif (params[:name].include?("admin"))
            @error = "Username cannot include 'admin'"
            haml :error
    	elsif (User.find_by_name(params[:name]))
    		@error = "User exists"
    		haml :error
    	else
    		user = User.generate(params[:name], params[:pw])
    		attachment "#{params[:name]}.p12"
    		"#{user.p12.to_der}"
    	end
    end

    get '/cert/request' do
    	haml :certreq
    end

    get '/cert/get' do
    	require_auth()

    	user = User.find_by_name(params[:name])
    	if (user and user.cert)
    		content_type :plain
			"#{user.cert}"
		else
			@error = "No such user, or no certificate on file."
			halt 500, "#{haml :error}"
		end
	end

end


