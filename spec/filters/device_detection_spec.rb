# encoding: utf-8
require_relative '../spec_helper'
require "logstash/filters/device_detection"

DATAFILE = ::Dir.glob(::File.expand_path("../../vendor/", ::File.dirname(__FILE__))+"/51Degrees-LiteV3.2.dat").first

describe LogStash::Filters::DeviceDetection do

  describe "defaults" do
    let(:config) do <<-CONFIG
      filter {
        device_detection {
          #datafile => "#{DATAFILE}"
          source => "user_agent"
          target => "device_detection"
          properties => ["BrowserName","BrowserVersion","IsMobile"]
        }
      }
    CONFIG
    end

    sample("user_agent" => "Mozilla/5.0 (Windows NT 6.3; WOW64; rv:41.0) Gecko/20100101 Firefox/41.0") do
      expect(subject.get('[device_detection][BrowserName]')).to eq('Firefox')
      expect(subject.get('[device_detection][BrowserVersion]')).to eq('41.0')
      expect(subject.get('[device_detection][IsMobile]')).to eq('False')
    end

  end


end
