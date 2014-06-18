require 'spec_helper'
require 'threatinator/registry'

describe Threatinator::Registry do
  let(:registry) { described_class.new }
  let(:ten_feeds) { 1.upto(10).map { |i| build(:feed, provider: "prov#{i}", name: "name#{i}") } }
  describe "#register" do
    it "should register the provided feed" do
      feed = build(:feed, provider: "my_provider", name: "my_name")
      registry.register(feed)
      expect(registry.get("my_provider", "my_name")).to be(feed)
    end
    it "should return the feed that was registered" do
      feed = build(:feed, provider: "my_provider", name: "my_name")
      expect(registry.register(feed)).to be(feed)
    end
    it "should raise a FeedAlreadyRegisteredError if a feed is already registered with the provider and name" do
      feed1 = build(:feed, provider: "my_provider", name: "my_name")
      feed2 = build(:feed, provider: "my_provider", name: "my_name")
      registry.register(feed1)
      expect { 
        registry.register(feed2)
      }.to raise_error(Threatinator::Exceptions::FeedAlreadyRegisteredError)
    end

    it "should raise a FeedAlreadyRegisteredError if the same feed is registered twice" do
      feed = build(:feed, provider: "my_provider", name: "my_name")
      registry.register(feed)
      expect { 
        registry.register(feed)
      }.to raise_error(Threatinator::Exceptions::FeedAlreadyRegisteredError)
    end
  end

  describe "#each" do
    it "should enumerate through each reigstered feed" do
      ten_feeds.each do |feed|
        registry.register(feed)
      end
      found_feeds = []
      registry.each do |feed|
        found_feeds << feed
      end
      expect(found_feeds).to match_array(ten_feeds)
    end
  end

  describe "#count" do
    it "should return the number of feeds contained within the registry" do
      expect(registry.count).to eq(0)
      ten_feeds.each do |feed|
        registry.register(feed)
      end
      expect(registry.count).to eq(10)
    end
  end

  describe "#get" do
    it "should return nil if the provider/name isn't registered" do
      registry.register(build(:feed, provider: "my_provider", name: "my_name"))
      expect(registry.get("asdf", "1234")).to be_nil
    end
    it "should return the correct feed for the given provider and name" do
      ten_feeds.each { |feed| registry.register(feed) }
      feed = build(:feed, provider: "my_provider", name: "my_name")
      registry.register(feed)
      expect(registry.get("my_provider", "my_name")).to be(feed)
    end
  end
end