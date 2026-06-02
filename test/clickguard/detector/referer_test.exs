defmodule Clickguard.Detector.RefererTest do
  use ExUnit.Case, async: true

  alias Clickguard.Detector.Referer
  alias Clickguard.EventBuilder, as: EB

  @base_ts ~U[2016-05-24 13:26:08.003Z]
  @custom_spam_domains ["semalt.com", "badtestdomain.com"]

  describe "detect/2 - common tests for all rules" do
    test "event with valid referer produces no findings" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "http://gooddomain.com")
      assert Referer.detect([event], spam_domains: @custom_spam_domains) == []
    end

    test "multiple rules per IP produce separate findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com")
      ]

      assert [f1, f2] = Referer.detect(events, spam_domains: @custom_spam_domains)
      rules = [f1, f2] |> Enum.map(& &1.rule) |> Enum.sort()
      assert rules == [:empty_referer, :spam_referer]
    end

    test "one rule per IP produces separate findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 2}, @base_ts, referer: "http://semalt.com")
      ]

      assert [f1, f2] = Referer.detect(events, spam_domains: @custom_spam_domains)
      rules = [f1, f2] |> Enum.map(& &1.rule) |> Enum.sort()
      subjects = [f1, f2] |> Enum.map(& &1.subject) |> Enum.sort()
      matched = [f1, f2] |> Enum.flat_map(& &1.evidence.matched_referers)
      assert rules == [:empty_referer, :spam_referer]
      assert subjects == ["127.0.0.1", "127.0.0.2"]
      assert matched == ["semalt.com"]
    end
  end

  describe ":detect/2 - :empty_referer rule" do
    test "event without referer produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: nil)
      assert [f] = Referer.detect([event], [])
      assert f.rule == :empty_referer
      assert f.severity == :low
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 1
      assert f.evidence.matched_referers == []
    end

    test "event with whitespace-only referer produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "    ")
      assert [f] = Referer.detect([event], [])
      assert f.rule == :empty_referer
      assert f.evidence.matched_referers == []
    end

    test "two events with different IPs produce two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 2}, @base_ts, referer: nil)
      ]

      assert [f1, f2] = Referer.detect(events, [])
      assert f1.subject in ["127.0.0.1", "127.0.0.2"]
      assert f2.subject in ["127.0.0.1", "127.0.0.2"]
      assert f1.subject != f2.subject
      assert f1.evidence.matched_referers == f2.evidence.matched_referers
    end

    test "two events with the same IP produce one finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil),
        EB.event({127, 0, 0, 1}, @base_ts, referer: nil)
      ]

      assert [f] = Referer.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 2
      assert f.evidence.matched_referers == []
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
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 4
      assert length(f.evidence.matched_referers) == 1
      assert f.evidence.matched_referers == ["semalt.com"]
    end

    test "finding shape" do
      event = EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com")

      assert [f] = Referer.detect([event], spam_domains: @custom_spam_domains)
      assert f.rule == :spam_referer
      assert f.severity == :low
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 1
      assert f.evidence.matched_referers == ["semalt.com"]
      assert f.sample_events == [event]
    end

    test "skips garbage referer" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "garbage"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "Garbage"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "GARBAGE")
      ]

      assert Referer.detect(events, spam_domains: @custom_spam_domains) == []
    end

    test "two different spam domains produce one findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://semalt.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "https://badtestdomain.com")
      ]

      assert [f] = Referer.detect(events, spam_domains: @custom_spam_domains)
      assert "semalt.com" in f.evidence.matched_referers
      assert "badtestdomain.com" in f.evidence.matched_referers
      assert f.rule == :spam_referer
      assert f.subject == "127.0.0.1"
      assert length(f.evidence.matched_referers) == 2
    end

    test "use default domain list" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://www.Brandedleadgeneration.com"),
        EB.event({127, 0, 0, 1}, @base_ts, referer: "http://BRANDEDLEADGENERATION.COM")
      ]

      assert [f] = Referer.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 4
      assert length(f.evidence.matched_referers) == 1
      assert f.evidence.matched_referers == ["brandedleadgeneration.com"]
    end
  end
end
