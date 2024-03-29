Pod::Spec.new do |s|
  s.name             = 'Krypt'
  s.version          = '1.8.0'
  s.summary          = 'Crypto used in Vivy iOS app'
  s.description      = s.summary
  s.homepage         = 'https://vivy.com'
  s.license          = { :type => 'MIT', :file => 'LICENSE' }
  s.author           = { 'Vivy GmbH' => 'ios@vivy.com' }
  s.source           = { :git => 'git@github.com:VivyTeam/krypt-ios.git', :tag => s.version.to_s }
  s.social_media_url = 'https://twitter.com/vivy_health'

  s.ios.deployment_target = '12.0'

  s.source_files = 'Krypt/Source/**/*.{swift,c,h}'
  s.preserve_path = 'Krypt/Source/module.map'

  s.pod_target_xcconfig = {
    'OTHER_LDFLAGS' => '$(inherited) -weak_framework CryptoKit',
    'SWIFT_INCLUDE_PATHS' => '$(SRCROOT)/Krypt/Krypt/Source'
  }

  s.dependency 'OpenSSL', '1.1.1q'
  s.dependency 'CryptoSwift', '~> 1.0'
  s.dependency 'RFC2046'
end
