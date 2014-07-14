require 'spec_helper'

describe 'feeds/musectech-ip_reputation.feed', :feed do
  let(:provider) { 'musectech' }
  let(:name) { 'ip_reputation' }

  it_fetches_url 'http://www.musectech.com/omens/omenshare.txt'

  describe_parsing_the_file feed_data('musectech_iplist.txt') do
    it "should have parsed 8 records" do
      expect(num_records_parsed).to eq(8)
    end
    it "should have filtered 17 records" do
      expect(num_records_filtered).to eq(17)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record 'VTI:80.82.64.42:Suspect IP - Positive Match in VirusTotal:Shr=Y:Wgt=1' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['80.82.64.42']) }
    end
  end

  describe_parsing_a_record 'VTI:195.225.105.196:Suspect IP - Positive Match in VirusTotal:Shr=Y:Wgt=4' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['195.225.105.196']) }
    end
  end
end


