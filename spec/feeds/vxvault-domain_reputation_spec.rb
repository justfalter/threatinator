require 'spec_helper'

describe 'feeds/vxvault-domain_reputation.feed', :feed do
  let(:provider) { 'vxvault' }
  let(:name) { 'domain_reputation' }

  it_fetches_url 'http://vxvault.siri-urz.net/URL_List.php'

  describe_parsing_the_file feed_data('vxvault_domainlist.txt') do
    it "should have parsed 17 records" do
      expect(num_records_parsed).to eq(17)
    end
    it "should have filtered 3 records" do
      expect(num_records_filtered).to eq(3)
    end
    it "should have missed 8 records" do
      expect(num_records_missed).to eq(8)
    end
  end

  describe_parsing_a_record 'http://www.miradacircle.com/_themes/exp/adobe_flash.exe' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:malware_host) }
      its(:fqdns) { is_expected.to match_array(["www.miradacircle.com"]) }
    end
  end

  describe_parsing_a_record 'http://dlc.infosyneris.ru/download/93/5/vn5PL27bfz6OnupYOxMzWxsPUhtzazcXBy4LXw93GxJvEwpfe38/j183Qrv6xt6b49GsoK729fj/ODj6uLi87CtLyFsrjgDlOVdg/fizruk_satrip.exe?pack' do
    it "should have parsed" do
      expect(status).to eq(:parsed)
    end
    it "should have parsed 1 event" do
      expect(events.count).to eq(1)
    end
	describe 'event 0' do
      subject { events[0] }
      its(:type) { is_expected.to be(:malware_host) }
      its(:fqdns) { is_expected.to match_array(["dlc.infosyneris.ru"]) }
    end
  end
end


