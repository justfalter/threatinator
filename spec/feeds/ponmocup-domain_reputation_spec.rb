require 'spec_helper'

describe 'feeds/ponmocup-domain_reputation.feed', :feed do
  let(:provider) { 'security-research' }
  let(:name) { 'ponmocup_domain_reputation' }

  it_fetches_url 'http://security-research.dyndns.org/pub/botnet/ponmocup/ponmocup-finder/ponmocup-infected-domains-latest.txt'

  describe_parsing_the_file feed_data('ponmocup_domainlist.txt') do
    it "should have parsed 18 records" do
      expect(num_records_parsed).to eq(18)
    end
    it "should have filtered 10 records" do
      expect(num_records_filtered).to eq(10)
    end
    it "should have missed 0 records" do
      expect(num_records_missed).to eq(0)
    end
  end

  describe_parsing_a_record 'checking domain: www.hostal3soles.com --> seems to be INFECTED: http://besidesdream.com/cgi-bin/r.cgi --> DNS: besidesdream.com / 91.237.88.230' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:c2) }
      its(:fqdns) { is_expected.to match_array(["besidesdream.com", "www.hostal3soles.com"]) }
    end
  end

  describe_parsing_a_record 'checking domain: www.creativ-art1.com --> seems to be INFECTED: http://vermillon.serenehomeandlandscapes.com/s --> DNS: vermillon.serenehomeandlandscapes.com / 81.92.219.61' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:c2) }
      its(:fqdns) { is_expected.to match_array(["vermillon.serenehomeandlandscapes.com", "www.creativ-art1.com"]) }
    end
  end
end


