Gem::Specification.new do |s|
  s.name          = 'logstash-filter-device_detection'
  s.version       = '1.0.1'
  s.licenses      = ['Apache License (2.0)']
  s.summary       = 'Use 51Degrees Device Detection library to parse User-Agent string'
  s.authors       = ['lalex']
  s.email         = 'github@lalex.nsk.ru'
  s.homepage      = 'https://github.com/lalex/logstash-filter-device_detection'
  s.platform      = "java"
  s.require_paths = ['lib']

  # Files
  s.files = Dir['lib/**/*','spec/**/*','vendor/**/*','*.gemspec','*.md','Gemfile','LICENSE','NOTICE.TXT']
   # Tests
  s.test_files = s.files.grep(%r{^(test|spec|features)/})

  # Special flag to let us know this is actually a logstash plugin
  s.metadata = { "logstash_plugin" => "true", "logstash_group" => "filter" }

  # Gem dependencies
  s.add_runtime_dependency "logstash-core-plugin-api", "~> 2.0"
  s.add_development_dependency 'logstash-devutils'

  # Jar dependencies
  s.requirements << "jar 'com.51degrees:device-detection-core', '3.2.14.2'"
  s.add_development_dependency 'jar-dependencies', '~> 0.3.2'
end
