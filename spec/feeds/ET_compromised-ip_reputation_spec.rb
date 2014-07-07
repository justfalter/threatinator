require 'spec_helper'

describe 'feeds/ET_compromised-ip_reputation.feed', :feed do
  let(:provider) { 'emergingthreats' }
  let(:name) { 'compromised_ip_reputation' }

  it_fetches_url 'http://rules.emergingthreats.net/open/suricata/rules/compromised-ips.txt'

  describe_parsing_the_file feed_data('ET_compromised-ip_reputation.txt') do
    it "should have parsed 11 records" do
      expect(num_records_parsed).to eq(11)
    end
    it "should have filtered 0 records" do
      expect(num_records_filtered).to eq(0)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record '1.93.24.90' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['1.93.24.90']) }
    end
  end

  describe_parsing_a_record '1.93.26.32' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['1.93.26.32']) }
    end
  end
end


