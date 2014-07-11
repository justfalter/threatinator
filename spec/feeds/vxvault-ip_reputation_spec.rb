require 'spec_helper'

describe 'feeds/vxvault-ip_reputation.feed', :feed do
  let(:provider) { 'vxvault' }
  let(:name) { 'ip_reputation' }

  it_fetches_url 'http://vxvault.siri-urz.net/URL_List.php'

  describe_parsing_the_file feed_data('vxvault_iplist.txt') do
    it "should have parsed 7 records" do
      expect(num_records_parsed).to eq(7)
    end
    it "should have filtered 20 records" do
      expect(num_records_filtered).to eq(20)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record 'http://91.188.124.171/zpm.exe' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:malware_host) }
      its(:ipv4s) { is_expected.to match_array(['91.188.124.171']) }
    end
  end

  describe_parsing_a_record 'http://46.22.166.244/zpm.exe' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:malware_host) }
      its(:ipv4s) { is_expected.to match_array(['46.22.166.244']) }
    end
  end
end


