Pod::Spec.new do |s|
  s.name             = 'Krypt'
  s.version          = '1.3.0'
  s.summary          = 'Crypto used in Vivy iOS app'
  s.description      = <<-DESC
  Crypto used in Vivy iOS app.
                       DESC
  s.homepage         = 'https://vivy.com'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Vivy GmbH' => 'ios@vivy.com' }
  s.source           = { :git => 'https://github.com/UvitaTeam/krypt-ios.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/vivy_health'

  s.ios.deployment_target = '11.0'

  s.source_files = 'Krypt/Source/**/*.{swift,c,h}'
  s.preserve_path = 'Krypt/Source/module.map'

  s.pod_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) $(PROJECT_DIR)/OpenSSL/OpenSSL/lib/libcrypto.a $(PROJECT_DIR)/OpenSSL/OpenSSL/lib/libssl.a',
    'LIBRARY_SEARCH_PATHS' => '$(PROJECT_DIR)/OpenSSL/OpenSSL/lib/',
    'SWIFT_INCLUDE_PATHS' => '$(SRCROOT)/Krypt/Krypt/Source'
  }
  
  s.dependency 'OpenSSL', '~> 1.1.1b'
  s.dependency 'CryptoSwift'
  s.dependency 'RFC2046'
end
