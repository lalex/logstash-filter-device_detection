# encoding: utf-8
require "logstash/filters/base"
require "logstash/namespace"

require "logstash-filter-device_detection_jars.rb"

# [NOTE]
# --
# This product includes Device Detection data created by 51Degrees, available from
# https://51degrees.com/. This database is licensed under
# http://www.mozilla.org/MPL/2.0/[Mozilla Public License 2].
# --

class LogStash::Filters::DeviceDetection < LogStash::Filters::Base

  config_name "device_detection"

  # The field containing the User-Agent header string.
  config :source, :validate => :string, :default => 'user_agent'

  # Specify the field into which Logstash should store the device data.
  config :target, :validate => :string, :default => 'device_match'

  # Path to 51Degrees Device Detection data file. Only BinaryV32 format is supported now.
  #
  # If not specified, this will default to the 51Degrees Device Detection database
  # that ships with Logstash.
  config :datafile, :validate => :path

  # Cache size for Device Detection library.
  #
  # This MUST be set to a value > 0.
  config :cache_size, :validate => :number, :default => 1000

  # An array of device properties to be included in the event.
  #
  # For the full property dictionary refer to
  # https://51degrees.com/resources/property-dictionary
  config :properties, :validate => :array

  public
  def register

    if @datafile.nil?
      @datafile = ::Dir.glob(::File.expand_path("../../../vendor/", ::File.dirname(__FILE__))+"/51Degrees-LiteV3.2.dat").first

      if @datafile.nil? || !::File.exists?(@datafile)
        raise "You must specify 'datafile => ...' in your device_detection filter (currently is set to '#{@datafile}')"
      end
    end

    begin
      dataset = Java::FiftyoneMobileDetectionFactories::StreamFactory.create(@datafile, false)
      @provider = Java::FiftyoneMobileDetection::Provider.new(dataset, @cache_size)
    rescue StandardError => e
      @logger.error("Error while initializing device detection provider object", :exception => e)
      return
    end

  end # def register

  public
  def filter(event)
    begin

      begin
        match = @provider.match(event.get(@source))
      rescue StandardError => e
        @logger.error("Error while parsing user agent data", :exception => e, :field => @source, :event => event)
        return
      end

      return unless match

      apply_match(match, event)

      #event.set(@target, match.getValues("IsMobile").toString())

    rescue Exception=>e
        @logger.error("Failed to detect device", :exception => e, :field => @source)
    end

    # filter_matched should go in the last line of our successful code
    filter_matched(event)
  end # def filter

  def apply_match(match, event)
    @properties.each do |property|
      field = "[#{@target}][#{property}]"
      value = match.getValues(property)
      event.set(field, value.toString()) if value
    end
    true
  end

end # class LogStash::Filters::Browser
