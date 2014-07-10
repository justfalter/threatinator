require 'spec_helper'

describe 'feeds/packetmail-ip_reputation.feed', :feed do
  let(:provider) { 'packetmail' }
  let(:name) { 'ip_reputation' }

  it_fetches_url 'https://www.packetmail.net/iprep.txt'

  describe_parsing_the_file feed_data('packetmail_iplist.txt') do
    it "should have parsed 9 records" do
      expect(num_records_parsed).to eq(9)
    end
    it "should have filtered 30 records" do
      expect(num_records_filtered).to eq(30)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record '188.176.247.10; 2014-07-09 00:03:14; Honeypot hits in 3600 hash-collection seconds: 2; Cumulative honeypot hits for IP over all days: 4' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['188.176.247.10']) }
    end
  end

  describe_parsing_a_record '117.41.186.155; 2014-07-09 00:03:15; Honeypot hits in 3600 hash-collection seconds: 3; Cumulative honeypot hits for IP over all days: 7' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['117.41.186.155']) }
    end
  end
end


