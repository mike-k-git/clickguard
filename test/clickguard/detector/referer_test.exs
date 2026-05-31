defmodule Clickguard.Detector.RefererTest do
  use ExUnit.Case, async: true

  alias Clickguard.Detector.Referer
  alias Clickguard.EventBuilder, as: EB

  @base_ts ~U[2016-05-24 13:26:08.003Z]
  @custom_spam_domains ["semalt.com", "badtestdomain.com"]

  describe "detect/2 - :empty_referer rule" do
    test "event with valid referer produces no findings" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "http://gooddomain.com")
      assert Referer.detect([event], []) == []
    end

    test "event without referer produces (none) finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: nil)
      assert [f] = Referer.detect([event], [])
      assert f.subject == "(none)"
    end

    test "finding shape" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: nil)

      assert [f] = Referer.detect([event], [])
      assert f.rule == :empty_referer
      assert f.severity == :low
      assert f.subject == "(none)"
      assert f.evidence.event_count == 1
      assert f.evidence.ips == ["127.0.0.1"]
      assert f.evidence.ips_truncated == false
      assert f.evidence.matched_value == nil
      assert f.sample_events == [event]
    end

    test "event with whitespace-only referer produces (none) finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "    ")
      assert [f] = Referer.detect([event], [])
      assert f.subject == "(none)"
    end

    test "events with nil and whitespace-only referers collapse into one finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 2}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 3}, @base_ts, referer: " "),
        EB.event({127, 0, 0, 4}, @base_ts, referer: "   ")
      ]

      assert [f] = Referer.detect(events, [])
      assert f.subject == "(none)"
      assert f.evidence.event_count == 4
      assert length(f.evidence.ips) == 4
      assert "127.0.0.1" in f.evidence.ips
      assert "127.0.0.2" in f.evidence.ips
      assert "127.0.0.3" in f.evidence.ips
      assert "127.0.0.4" in f.evidence.ips
      assert f.evidence.ips_truncated == false
    end

    test "there are only unique IPs in finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 1}, @base_ts, referer: " "),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "   ")
      ]

      assert [f] = Referer.detect(events, [])
      assert f.subject == "(none)"
      assert f.evidence.event_count == 4
      assert length(f.evidence.ips) == 1
      assert "127.0.0.1" in f.evidence.ips
    end
  end

  describe "detect/2 - :spam_referer rule" do
    test "normalizes domain name" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.semalt.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.Semalt.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://SEMALT.COM")
      ]

      assert [f] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert f.subject == "semalt.com"
      assert f.evidence.event_count == 4
      assert length(f.evidence.ips) == 1
      assert "127.0.0.1" in f.evidence.ips
    end

    test "finding shape" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com")

      assert [f] = Referer.detect([event], spam_domains: @custom_spam_domains)
      assert f.rule == :spam_referer
      assert f.severity == :low
      assert f.subject == "semalt.com"
      assert f.evidence.event_count == 1
      assert f.evidence.ips == ["127.0.0.1"]
      assert f.evidence.ips_truncated == false
      assert f.evidence.matched_value == "semalt.com"
      assert f.sample_events == [event]
    end

    test "skips garbage referer" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "garbage"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "Garbage"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "GARBAGE")
      ]

      assert Referer.detect(events, []) == []
    end

    test "two different spam domains produce two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "https://badtestdomain.com")
      ]

      assert [f1, f2] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert "semalt.com" in [f1.subject, f2.subject]
      assert "badtestdomain.com" in [f1.subject, f2.subject]
    end

    test "ips is truncated" do
      events =
        for n <- 1..51,
            do: EB.event({127, 0, 0, n}, @base_ts, referer: "http://semalt.com")

      assert [f] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert f.subject == "semalt.com"
      assert f.evidence.event_count == 51
      assert length(f.evidence.ips) == 50
      assert f.evidence.ips_truncated == true
    end

    test "ips_truncated boundary" do
      events =
        for n <- 1..50,
            do: EB.event({127, 0, 0, n}, @base_ts, referer: "http://semalt.com")

      assert [f] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert f.subject == "semalt.com"
      assert f.evidence.event_count == 50
      assert length(f.evidence.ips) == 50
      assert f.evidence.ips_truncated == false
    end

    test "use default domain list" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.Brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://BRANDEDLEADGENERATION.COM")
      ]

      assert [f] = Referer.detect(events, [])
      assert f.subject == "brandedleadgeneration.com"
      assert f.evidence.event_count == 4
      assert length(f.evidence.ips) == 1
      assert "127.0.0.1" in f.evidence.ips
    end
  end

  describe "detect/2 both rules in one batch" do
    test "one :empty_referer event and one :spam_referer event produce exactly two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com"),
        EB.event({127, 0, 0, 2}, @base_ts, referer: nil)
      ]

      assert [f1, f2] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert f1.subject in ["semalt.com", "(none)"]
      assert f2.subject in ["semalt.com", "(none)"]
      assert f1.rule in [:empty_referer, :spam_referer]
      assert f2.rule in [:empty_referer, :spam_referer]
      assert f1.rule != f2.rule
      assert f1.subject != f2.subject
    end
  end
end
