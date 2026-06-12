defmodule Clickguard.Detector.ClickVelocityTest do
  use ExUnit.Case, async: true

  alias Clickguard.Detector.ClickVelocity
  alias Clickguard.Event
  alias Clickguard.EventBuilder, as: EB

  @base_ts ~U[2016-06-24 13:26:08.003Z]

  describe "detect/2" do
    test "6 clicks at ~600ms median → :high" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 6, 600)

      [finding] = ClickVelocity.detect(events, [])

      assert finding.rule == :click_velocity
      assert finding.severity == :high
      assert finding.evidence.median_delta_ms == 600.0
    end

    test "6 clicks at ~1500ms median → :medium" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 6, 1500)

      [finding] = ClickVelocity.detect(events, [])

      assert finding.rule == :click_velocity
      assert finding.severity == :medium
    end

    test "6 clicks at ~10s median → no finding" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 6, 10_000)

      [] = ClickVelocity.detect(events, [])
    end

    test "4 clicks at 500ms → no finding (min-size gate)" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 4, 500)

      [] = ClickVelocity.detect(events, [])
    end

    test "two 4-click runs separated by 40 min → no finding" do
      events =
        EB.burst({127, 0, 0, 1}, @base_ts, 4, 500) ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 40, :minute), 4, 500)

      [] = ClickVelocity.detect(events, [])
    end

    test "5 clicks inside one second within an otherwise slow 10-click session → :high via burst" do
      events =
        EB.burst({127, 0, 0, 1}, @base_ts, 5, 15_000) ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 5, :second), 5, 50)

      [finding] = ClickVelocity.detect(events, [])
      assert finding.severity == :high
      assert finding.evidence.max_burst == 5
      assert finding.evidence.median_delta_ms == 5000.0
    end

    test "same IP, two different UAs → two pairs, no cross-contamination" do
      events =
        EB.burst({127, 0, 0, 1}, @base_ts, 10, 500, user_agent: "test1") ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 5, :minute), 10, 500,
            user_agent: "test2"
          )

      [finding1, finding2] = ClickVelocity.detect(events, [])

      assert Enum.sort([finding1.subject, finding2.subject]) == [
               "127.0.0.1|test1",
               "127.0.0.1|test2"
             ]
    end

    test "one pair, two offending sessions → ONE finding, event_count = sum, severity = worst" do
      events =
        EB.burst({127, 0, 0, 1}, @base_ts, 10, 500) ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 10, 1_500)

      [finding] = ClickVelocity.detect(events, [])

      assert finding.severity == :high
      assert finding.evidence.event_count == 20
    end

    test "jitter intervals" do
      events = [
        EB.event({127, 0, 0, 1}, @base_ts),
        EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 100, :millisecond)),
        EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 200, :millisecond)),
        EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 60_200, :millisecond)),
        EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 60_300, :millisecond)),
        EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 60_400, :millisecond))
      ]

      [finding] = ClickVelocity.detect(events, [])

      assert finding.severity == :high
      assert finding.evidence.median_delta_ms == 100.0
    end

    test "min_session_clicks: 8 against a 6-click burst → []" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 6, 1500)

      [] = ClickVelocity.detect(events, min_session_clicks: 8)
    end

    test "sample_events contains events from the worst session" do
      worst = EB.burst({127, 0, 0, 1}, @base_ts, 6, 50)
      bad = EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 35, :minute), 6, 500)

      [finding] = ClickVelocity.detect(bad ++ worst, [])

      assert Event.sample(worst) == finding.sample_events
    end

    test "sample_events contains events from the worst session #2" do
      worst =
        EB.burst({127, 0, 0, 1}, @base_ts, 5, 15_000) ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 5, :second), 5, 50)

      bad = EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 35, :minute), 6, 1_500)

      [finding] = ClickVelocity.detect(bad ++ worst, [])

      assert finding.severity == :high
      assert finding.evidence.max_burst == 5
      assert finding.evidence.median_delta_ms == 5000

      assert Event.sample(worst |> Enum.sort_by(& &1.timestamp, DateTime)) ==
               finding.sample_events
    end
  end
end
