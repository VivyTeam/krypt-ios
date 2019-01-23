Pod::Spec.new do |s|
  s.name             = 'Krypt'
  s.version          = '0.1.0'
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
  s.source_files = 'Krypt/Source/*.swift'
  s.dependency 'CryptoSwift'
end
