require 'oauth/consumer'
require 'oauth2'
require 'net/https'
require 'uri'

class HomeController < ApplicationController
  API_KEY = 'j44tao2udvcl'
  API_SECRET = 'lo1LEkc9AF6kmkLj'
  # API_KEY = 'lk8h5a5ql29t'
  # API_SECRET = 'j34PFSLbN9YjJaRg'
  REDIRECT_URI = 'http://0.0.0.0:3000/accept'
  # REDIRECT_URI = 'http://www.google.com'
  
  def client
    OAuth2::Client.new(
       API_KEY,
       API_SECRET, 
       :authorize_url => "/uas/oauth2/authorization?response_type=code", 
       :token_url => "/uas/oauth2/accessToken",
       :site => "https://www.linkedin.com"
     )
  end
  
  def index
    debugger
     
    authorize_oauth2
    # authorize
    # authorize_ei
    # auth_test
  end
  
  def auth_test
    redirect_to "https://www.linkedin.com/uas/oauth2/authorization?response_type=code&client_id="+ API_KEY + "&state=STATE&redirect_uri=http://0.0.0.0:3000/accept"
    # redirect_to 'https://www.linkedin.com/uas/oauth2/authorization?response_type=code&client_id=jf2wmzgoih7d&scope=r_basicprofile&state=ZZZ456&redirect_uri=http%3A%2F%2F0.0.0.0%3A3000%2Faccept'
  end
  
  def accept
    debugger
    code = params[:code] 
         
    access_token = client.auth_code.get_token(code, :redirect_uri => REDIRECT_URI, :state => "thisisatest")
    
    puts access_token.token
         
        access_token = OAuth2::AccessToken.new(client, access_token.token, {
          :mode => :query,
          :param_name => "oauth2_access_token",
          })
        
        response = access_token.get('https://www.linkedin.com/v1/people/~')
        puts response.body
    
    # Retrieve access token object
    # code = params[:code]
    # 
    # authorize_user(code) 
  end
  
  def authorize_user(code)

    debugger
    uri = URI('https://www.linkedin.com/uas/oauth2/accessToken')

    # linkedin_uri = URI.parse('https://www.linkedin.com/uas/oauth2/accessToken?grant_type=authorization_code&code='+ code + '&redirect_uri=http://0.0.0.0:3000/accept&client_id=j44tao2udvcl&client_secret=lo1LEkc9AF6kmkLj')                      
    linkedin_uri = URI.parse('https://www.linkedin.com/uas/oauth2/accessToken')          
    https = Net::HTTP.new(linkedin_uri.host, linkedin_uri.port)    
    https.use_ssl = true                                                         
    https.verify_mode = OpenSSL::SSL::VERIFY_NONE                                
    postData = https.request_post(linkedin_uri.path,'grant_type=authorization_code&code='+ code +'&redirect_uri=http%3A%2F%2F0.0.0.0%3A3000%2Faccept&client_id=lk8h5a5ql29t&client_secret=j34PFSLbN9YjJaRg')
                                        
    # postData = request(uri,{'grant_type'=>'authorization_code', 'code' => code, 'redirect_uri' => 'http://0.0.0.0:3000/accept', 'client_id' => 'j44tao2udvcl', 'client_secret' => 'lo1LEkc9AF6kmkLj'})

    puts postData.body
  end
  
  def refresh_token
    # My Test API Key
    # api_key = 'oemg6g45iazj'
    # api_secret = 'SpiRaInhJ5sJcif3'
    api_key = 'ka3ft8c4bmhn'
    api_secret = 'RrZgpElvM5tW2ttV'
    configuration = { :site => 'https://www.linkedin.com',
                          :authorize_path => '/uas/oauth/authenticate',
                          :request_token_path => '/uas/oauth/requestToken?scope=r_fullprofile',
                          :access_token_path => '/uas/oauth/accessToken' }

    consumer = OAuth::Consumer.new(api_key, api_secret, configuration)
      
    #Request token
    @request_token = consumer.get_request_token

    session[:request_token] = @request_token
    redirect_to @request_token.authorize_url
    
  end
  
  def authorize_bi
    debugger
    # The following auth values belong in the config, but for the sake of this exercise will be hard coded
    api_key = 'lijpj1fmhpnn'
    api_secret = 'jYQX1xVuWEGpADQi'
    configuration = { :site => 'https://api.linkedin.com',
                          # :authorize_path => 'https://api.linkedin.com/uas/oauth/authorize',
                          :authorize_path => 'https://www.linkedin.com/uas/oauth/authenticate',
                          :request_token_path => 'https://api.linkedin.com/uas/oauth/requestToken?scope=r_emailaddress',
                          :access_token_path => 'https://api.linkedin.com/uas/oauth/accessToken' }

      consumer = OAuth::Consumer.new(api_key, api_secret, configuration)
      
      #Request token
      request_token = consumer.get_request_token

      # Output request URL to console
      puts "Please visit this URL: " + request_token.authorize_url + " in your browser and then input the numerical code you are provided here: "

      # Set verifier code
      verifier = $stdin.gets.strip

      # Retrieve access token object
      @access_token = request_token.get_access_token(:oauth_verifier => verifier)
      
      puts "\n " + @access_token.token
      puts "\n " + @access_token.secret
  end
  
  def authorize
    # debugger
    # # The following auth values belong in the config, but for the sake of this exercise will be hard coded
    # My Test API Key
    # api_key = 'ka3ft8c4bmhn'
    # api_secret = 'RrZgpElvM5tW2ttV'
    #api_key = 'oemg6g45iazj'
    #api_secret = 'SpiRaInhJ5sJcif3'
    # # Spredfast
    # # api_key = 'fTc795B5Fh8dEOe-hD_kS_M3mNcuaoY3SY5vGRaR1c7TYN9xy9b2eWkYXerQquv2'
    # # api_secret = 'khF0i3jAdtrh60ek0e7xbcGwBaMy-SdtY5VnbMHa5gPYdnKjdktoNFPxwiuvixC7'
    # Apple
    # api_key = 'kh01xktixcow'
    # api_secret = 'zMfj5CFuIT9czqLb'
    # configuration = { :site => 'https://www.linkedin.com',
    #                       :authorize_path => '/uas/oauth/authenticate',
    #                       # :request_token_path => '/uas/oauth/requestToken?scope=r_fullprofile+r_emailaddress+rw_nus',
    #                       :request_token_path => '/uas/oauth/requestToken',
    #                       :access_token_path => '/uas/oauth/accessToken' }
    # 
    #   consumer = OAuth::Consumer.new(api_key, api_secret, configuration)
    #   
    #   #Request token
    #   @request_token = consumer.get_request_token(:oauth_callback => "http://localhost:3000/accept")
    #   session[:request_token] = @request_token
    #   
    #   # Output request URL to console
    #   #puts "Please visit this URL: https://www.linkedin.com/uas/oauth/authenticate?oauth_token=" + request_token.token  + " in your browser and then input the numerical code you are provided here: "
    #   redirect_to @request_token.authorize_url(:oauth_callback => "http://localhost:3000/accept")
    
    
    configuration = { :site => 'https://www.linkedin.com',
                          :authorize_path => '/uas/oauth/authenticate',
                          :request_token_path => '/uas/oauth/requestToken?scope=r_network+r_fullprofile+r_emailaddress+r_basicprofile+rw_nus',
                          # :request_token_path => '/uas/oauth/requestToken',
                          :access_token_path => '/uas/oauth/accessToken' }
    
    
    consumer = OAuth::Consumer.new(API_KEY, API_SECRET, configuration)

    #Request token
    request_token = consumer.get_request_token

    # Output request URL to console
    puts "Please visit this URL: https://www.linkedin.com/uas/oauth/authenticate?oauth_token=" + request_token.token  + " in your browser and then input the numerical code you are provided here: "

    # Set verifier code
    verifier = $stdin.gets.strip

    # Retrieve access token object
    @access_token = request_token.get_access_token(:oauth_verifier => verifier)

    puts "\n " + @access_token.token
    puts "\n " + @access_token.secret
      
  end
    
  def authorize_ei
       # The following auth values belong in the config, but for the sake of this exercise will be hard coded
       # Kamyar Test App
       api_key = 'd9w9kflpfnkv'
       api_secret = 'iaq7waopLQ6WIKgg'
       # Shikha Test App
       # api_key = 'gxzti1edfjw5'
       # api_secret = 'Id9ga0JATiCqUYcR'
       
       configuration = { :site => 'https://api.linkedin-ei.com',
                             :authorize_path => 'https://api.linkedin-ei.com/uas/oauth/authenticate',
                             :request_token_path => 'https://api.linkedin-ei.com/uas/oauth/requestToken',
                             :access_token_path => 'https://api.linkedin-ei.com/uas/oauth/accessToken' }
       
       
       consumer = OAuth::Consumer.new(api_key, api_secret, configuration)

       debugger
       
       #Request token
       request_token = consumer.get_request_token

       # Output request URL to console
       puts "Please visit this URL: https://api.linkedin-ei.com/uas/oauth/authenticate?oauth_token=" + request_token.token  + " in your browser and then input the numerical code you are provided here: "

       # Set verifier code
       verifier = $stdin.gets.strip

      
       # Retrieve access token object
       @access_token = request_token.get_access_token(:oauth_verifier => verifier)

       puts "\n " + @access_token.token
       puts "\n " + @access_token.secret 
     end
     
   def authorize_ads
     debugger
     # The following auth values belong in the config, but for the sake of this exercise will be hard coded
     api_key = 'ogwrozejktjx'
     api_secret = 'GCA8WEco1jX4FVze'

     configuration = { :site => 'http://force.linkedinlabs.com:8080',
                              :authorize_path => 'http://force.linkedinlabs.com:8080/uas/oauth/authorize',
                              :request_token_path => 'http://force.linkedinlabs.com:8080/uas/oauth/requestToken',
                              :access_token_path => 'http://force.linkedinlabs.com:8080/uas/oauth/accessToken' }

     consumer = OAuth::Consumer.new(api_key, api_secret, configuration)

       #Request token
       request_token = consumer.get_request_token

       puts "Please visit this URL: " + request_token.authorize_url + " in your browser and then input the numerical code you are provided here: "

       # Set verifier code
       verifier = $stdin.gets.strip

       # Retrieve access token object
       @access_token = request_token.get_access_token(:oauth_verifier => verifier)           
       
       puts "\n " + @access_token.token
       puts "\n " + @access_token.secret
   end

   def authorize_oauth2
     debugger
     
     redirect_to client.auth_code.authorize_url(:scope => 'r_network r_fullprofile r_emailaddress', :state => 'thisisatest', :redirect_uri => REDIRECT_URI)
   end
end