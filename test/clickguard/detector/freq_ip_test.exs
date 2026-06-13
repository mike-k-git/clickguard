defmodule Clickguard.Detector.FreqIpTest do
  use ExUnit.Case, async: true

  alias Clickguard.Detector.FreqIp
  alias Clickguard.EventBuilder, as: EB
  alias Clickguard.Finding

  @base_ts ~U[2016-05-24 13:26:08.003Z]

  describe "detect/2 - threshold / window behaviour" do
    test "events below threshold produce no findings" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 299, 10)

      assert FreqIp.detect(events, []) == []
    end

    test "events exactly at threshold produce one finding" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)

      assert [_] = FreqIp.detect(events, [])
    end

    test "events spread over too long a window produce no findings" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 3000, 10_000)

      assert FreqIp.detect(events, []) == []
    end

    test "no events produce no findings" do
      assert FreqIp.detect([], []) == []
    end
  end

  describe "detect/2 - multiple IPs" do
    test "two IP's, only one exceeds threshold, produce one finding" do
      bad = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)
      good = EB.burst({127, 0, 0, 2}, @base_ts, 299, 10)
      events = bad ++ good

      assert [f] = FreqIp.detect(events, [])
      assert f.subject == "127.0.0.1"
    end

    test "two IP's, both exceed threshold, produce two findings" do
      bad = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)
      worse = EB.burst({127, 0, 0, 2}, @base_ts, 500, 10)
      events = bad ++ worse

      assert [f1, f2] = FreqIp.detect(events, [])
      assert f1.subject == "127.0.0.1"
      assert f2.subject == "127.0.0.2"
    end
  end

  describe "detect/2 - opts" do
    test "custom :threshold via opts overrides default" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 50, 10)

      assert [%Finding{evidence: %{threshold: 50}}] =
               FreqIp.detect(events, threshold: 50)
    end

    test "custom :window_ms via opts overrides default" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)

      assert [%Finding{evidence: %{window_ms: 10_000}}] =
               FreqIp.detect(events, window_ms: 10_000)
    end
  end

  describe "detect/2 - finding shape" do
    test "returned finding is of correct shape" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)

      assert [f] = FreqIp.detect(events, [])
      assert f.subject == "127.0.0.1"
      assert f.rule == :high_frequency_ip
      assert f.severity == :low
      assert f.actor_type == :ip

      assert %{
               event_count: event_count,
               threshold: threshold,
               window_ms: window_ms,
               window_start: window_start,
               window_end: window_end
             } = f.evidence

      assert event_count == 300
      assert threshold == 300
      assert window_ms == 60_000
      assert window_start == @base_ts
      assert window_end == DateTime.add(@base_ts, 299 * 10, :millisecond)
      assert length(f.sample_events) == 5
    end
  end

  describe "detect/2 - robustness" do
    test "unordered input is sorted and processed correctly" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10) |> Enum.shuffle()

      assert [_] = FreqIp.detect(events, [])
    end
  end

  describe "detect/2 - peak rate in evidence" do
    test "produced by the biggest window, not always the first" do
      first = EB.burst({127, 0, 0, 1}, @base_ts, 300, 10)

      biggest = EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 600, 10)

      assert [finding] = FreqIp.detect(first ++ biggest, [])
      assert finding.evidence.event_count == 300
      assert finding.evidence.peak_count == 600
    end
  end
end
