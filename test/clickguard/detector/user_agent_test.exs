defmodule Clickguard.Detector.UserAgentTest do
  use ExUnit.Case, async: true

  alias Clickguard.Detector.UserAgent
  alias Clickguard.EventBuilder, as: EB

  @base_ts ~U[2016-05-24 13:26:08.003Z]
  @automation_ua "python-requests/2.29.0"
  @headless_ua "Mozilla/5.0 (Windows NT 6.2; WOW64) AppleWebKit/534.34 (KHTML, like Gecko) PhantomJS/1.9.2 Safari/534.34"
  @good_ua "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:151.0) Gecko/20100101 Firefox/151.0"

  describe "detect/2 common tests for all rules" do
    test "event with valid user-agent produces no findings" do
      event =
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @good_ua)

      assert UserAgent.detect([event], []) == []
    end

    test "multiple rules per IP produce separate findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: nil),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @good_ua)
      ]

      assert [f1, f2, f3] = UserAgent.detect(events, [])
      rules = [f1, f2, f3] |> Enum.map(& &1.rule) |> Enum.sort()
      assert rules == [:automation_tool, :empty_ua, :headless_browser]
    end

    test "one rule per IP produces separate findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: nil),
        EB.event({127, 0, 0, 2}, @base_ts, user_agent: @automation_ua),
        EB.event({127, 0, 0, 3}, @base_ts, user_agent: @headless_ua),
        EB.event({127, 0, 0, 4}, @base_ts, user_agent: @good_ua)
      ]

      assert [f1, f2, f3] = UserAgent.detect(events, [])
      rules = [f1, f2, f3] |> Enum.map(& &1.rule) |> Enum.sort()
      subjects = [f1, f2, f3] |> Enum.map(& &1.subject) |> Enum.sort()
      assert rules == [:automation_tool, :empty_ua, :headless_browser]
      assert subjects == ["127.0.0.1", "127.0.0.2", "127.0.0.3"]
    end
  end

  describe "detect/2 - :empty_ua rule" do
    test "event without user-agent produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, user_agent: nil)
      assert [f] = UserAgent.detect([event], [])
      assert f.subject == "127.0.0.1"
      assert f.rule == :empty_ua
      assert f.actor_type == :ip
      assert f.evidence.event_count == 1
      assert f.evidence.matched_uas == []
      assert f.severity == :info
    end

    test "event with whitespace-only user-agent produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, user_agent: "    ")
      assert [f] = UserAgent.detect([event], [])
      assert f.rule == :empty_ua
      assert f.evidence.matched_uas == []
    end

    test "two events with different IPs produce two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: nil),
        EB.event({127, 0, 0, 2}, @base_ts, user_agent: nil)
      ]

      assert [f1, f2] = UserAgent.detect(events, [])
      assert f1.subject in ["127.0.0.1", "127.0.0.2"]
      assert f2.subject in ["127.0.0.1", "127.0.0.2"]
      assert f1.subject != f2.subject
      assert f1.evidence.matched_uas == f2.evidence.matched_uas
    end

    test "two events with the same IP produce one finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: nil),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: "    ")
      ]

      assert [f] = UserAgent.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.matched_uas == []
      assert f.evidence.event_count == 2
    end
  end

  describe "detect/2 - :automation_tool rule" do
    test "automation_tool user-agent produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua)
      assert [f] = UserAgent.detect([event], [])
      assert f.subject == "127.0.0.1"
      assert f.rule == :automation_tool
      assert f.actor_type == :ip
      assert f.evidence.event_count == 1
      assert f.evidence.matched_uas == [@automation_ua]
      assert f.severity == :low
    end

    test "two events with different IPs produce two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua),
        EB.event({127, 0, 0, 2}, @base_ts, user_agent: @automation_ua)
      ]

      assert [f1, f2] = UserAgent.detect(events, [])
      assert f1.subject in ["127.0.0.1", "127.0.0.2"]
      assert f2.subject in ["127.0.0.1", "127.0.0.2"]
      assert f1.subject != f2.subject
      assert f1.evidence.matched_uas == f2.evidence.matched_uas
      assert f1.evidence.matched_uas == [@automation_ua]
    end

    test "two events with the same IP and user-agent produce one finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua)
      ]

      assert [f] = UserAgent.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.matched_uas == [@automation_ua]
      assert f.evidence.event_count == 2
    end

    test "two events with the same IP produce one finding" do
      second_ua = "curl/8.3.0"

      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: second_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @automation_ua)
      ]

      assert [f1] = UserAgent.detect(events, [])
      assert f1.subject == "127.0.0.1"
      assert f1.evidence.event_count == 2
      assert length(f1.evidence.matched_uas) == 2
      assert f1.rule == :automation_tool
      assert second_ua in f1.evidence.matched_uas
      assert @automation_ua in f1.evidence.matched_uas
    end
  end

  describe "detect/2 - :headless_browser rule" do
    test "headless_browser user-agent produces one finding" do
      event = EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua)
      assert [f] = UserAgent.detect([event], [])
      assert f.subject == "127.0.0.1"
      assert f.rule == :headless_browser
      assert f.actor_type == :ip
      assert f.evidence.event_count == 1
      assert f.evidence.matched_uas == [@headless_ua]
      assert f.severity == :low
    end

    test "two events with different IPs produce two findings" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua),
        EB.event({127, 0, 0, 2}, @base_ts, user_agent: @headless_ua)
      ]

      assert [f1, f2] = UserAgent.detect(events, [])
      assert f1.subject in ["127.0.0.1", "127.0.0.2"]
      assert f2.subject in ["127.0.0.1", "127.0.0.2"]
      assert f1.subject != f2.subject
      assert f1.evidence.matched_uas == f2.evidence.matched_uas
      assert f1.evidence.matched_uas == [@headless_ua]
    end

    test "two events with the same IP and user-agent produce one finding" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua)
      ]

      assert [f] = UserAgent.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.matched_uas == [@headless_ua]
      assert f.evidence.event_count == 2
    end

    test "two events with the same IP produce one finding" do
      second_ua =
        "Mozilla/5.0 (X14; Linux x82_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/80.0.3987.132 Safari/537.36"

      events = [
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: second_ua),
        EB.event({127, 0, 0, 1}, @base_ts, user_agent: @headless_ua)
      ]

      assert [f] = UserAgent.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.evidence.event_count == 2
      assert length(f.evidence.matched_uas) == 2
      assert f.rule == :headless_browser
      assert second_ua in f.evidence.matched_uas
      assert @headless_ua in f.evidence.matched_uas
    end
  end
end
