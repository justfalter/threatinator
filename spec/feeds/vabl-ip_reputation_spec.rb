require 'spec_helper'

describe 'feeds/vabl-ip_reputation.feed', :feed do
  let(:provider) { 'vabl' }
  let(:name) { 'ip_reputation' }

  it_fetches_url 'http://www.infiltrated.net/vabl.txt'

  describe_parsing_the_file feed_data('vabl_iplist.txt') do
    it "should have parsed 18 records" do
      expect(num_records_parsed).to eq(18)
    end
    it "should have filtered 12 records" do
      expect(num_records_filtered).to eq(12)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record '108.59.1.5 | BRU | VABL | 20110726 | fb17621acd4b0626c80ba8e66e963518 | 30633 | 108.59.0.0/20 | LEASEWEB-US | US | - | LEASEWEB USA INC' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['108.59.1.5']) }
    end
  end

  describe_parsing_a_record '109.168.200.104 | ATK | HPOT | 20110819 | fb17621acd4b0626c80ba8e66e963518 | 34060 | 94.176.216.0/22 | TCCFR | RO | ELECTROSIM.RO | JUMP INTERNET SERVICES SRL' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:scanning) }
      its(:ipv4s) { is_expected.to match_array(['109.168.200.104']) }
    end
  end
end


