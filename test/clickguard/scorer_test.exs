defmodule Clickguard.ScorerTest do
  use ExUnit.Case, async: true

  @base_ts ~U[2016-05-24 13:26:08.003Z]

  alias Clickguard.{Event, Finding, Scorer}
  alias Clickguard.EventBuilder, as: EB

  describe "score/2 intensity scoring" do
    test "4 distinct lows, score >= 4 but band :suspect (cap for lows)" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 300, 50),
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 301, 5000),
          EB.event({127, 0, 0, 1}, @base_ts, user_agent: "curl"),
          EB.event({127, 0, 0, 1}, @base_ts, user_agent: "phantomjs"),
          EB.event({127, 0, 0, 1}, @base_ts, referer: "https://brandedleadgeneration.com")
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :suspect
      assert score.score == 4
      assert map_size(score.rule_summary) == 4
    end

    test "1 medium + 1 low -> :fraud (synthetic)" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 5, 1_500, user_agent: "fast-velocity"),
          EB.event({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), user_agent: "fast-velocity")
        ]
        |> List.flatten()

      finding = %Finding{
        rule: :fake_low_rule,
        severity: :low,
        subject: "127.0.0.1|fast-velocity",
        actor_type: :session,
        evidence: %{
          event_count: 10,
          matched_values: ["val1", "val2"]
        },
        sample_events: Event.sample(events),
        detected_at: DateTime.now!("Etc/UTC")
      }

      {:ok, findings} = Clickguard.detect(events, [])

      [score] = Scorer.score([finding | findings], Clickguard.actor_totals(events))
      assert score.band == :fraud
      assert score.score == 4
      assert map_size(score.rule_summary) == 2
    end

    test "high with ratio 1.0, total >= @min_sample -> boosted score, :fraud" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 25, 500, user_agent: "fast-velocity")

      {:ok, findings} = Clickguard.detect(events)

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :fraud
      assert score.score == 32
      assert map_size(score.rule_summary) == 1
      assert score.total_events == 25
    end

    test "high with ratio 1.0, total < @min_sample -> default score, :fraud" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 19, 500, user_agent: "fast-velocity")

      {:ok, findings} = Clickguard.detect(events)

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :fraud
      assert score.score == 16
      assert map_size(score.rule_summary) == 1
      assert score.total_events == 19
    end

    test "low with ratio 0.9, total >= @min_sample -> scored is doubled, but band is capped" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 300, 50),
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 30, 5000)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :suspect
      assert score.score == 2
      assert map_size(score.rule_summary) == 1
    end

    test "ratio below @ratio_floor -> no score boost" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 600, 50),
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 1000, 5000)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :clear
      assert score.score == 1
      assert map_size(score.rule_summary) == 1
    end

    test "score boost for hygiene rules doesn't affect the results" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 50, 5_000, user_agent: nil)

      {:ok, findings} = Clickguard.detect(events, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.band == :clear
      assert score.score == 0
      assert map_size(score.rule_summary) == 1
    end

    test "boost boundaries: N is less than @min_sample -> unboosted :medium" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 19, 2_000, user_agent: "high-velocity")
      events2 = EB.burst({127, 0, 0, 2}, @base_ts, 20, 2_000, user_agent: "high-velocity")

      {:ok, findings} = Clickguard.detect(events, [])
      {:ok, findings2} = Clickguard.detect(events2, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      [score2] = Scorer.score(findings2, Clickguard.actor_totals(events2))

      assert score.band == :suspect
      assert score.score == 3
      assert map_size(score.rule_summary) == 1

      assert score2.band == :fraud
      assert score2.score == 6
      assert map_size(score2.rule_summary) == 1
    end

    test "boost boundaries: ratio is less than @ratio_floor -> unboosted :medium" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 50, 2_000, user_agent: "high-velocity"),
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 51, 2_500,
            user_agent: "high-velocity"
          )
        ]
        |> List.flatten()

      events2 = EB.burst({127, 0, 0, 2}, @base_ts, 20, 2_000, user_agent: "high-velocity")

      {:ok, findings} = Clickguard.detect(events, [])
      {:ok, findings2} = Clickguard.detect(events2, [])

      [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      [score2] = Scorer.score(findings2, Clickguard.actor_totals(events2))

      assert score.band == :suspect
      assert score.score == 3
      assert map_size(score.rule_summary) == 1

      assert score2.band == :fraud
      assert score2.score == 6
      assert map_size(score2.rule_summary) == 1
    end
  end

  describe "score/2" do
    test "produces no scores without findings" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000)
      {:ok, findings} = Clickguard.detect(events, [])

      assert Scorer.score(findings, Clickguard.actor_totals(events)) == []
    end

    test "produces :clear score for :epmty_referer detection" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000, referer: nil)
      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_referer: {:info, 10}}
      assert score.score == 0
      assert score.total_events == 10
      assert score.total_findings == 1
    end

    test "produces :clear score for :empty_ua detection" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000, user_agent: nil)
      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:info, 10}}
      assert score.score == 0
      assert score.total_events == 10
      assert score.total_findings == 1
    end

    test "produces :clear score for two distinct :empty_* detections" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000, user_agent: nil),
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000, referer: nil)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:info, 10}, empty_referer: {:info, 10}}
      assert score.score == 0
      assert score.total_events == 20
      assert score.total_findings == 2
    end

    test "produces :clear score for one :empty_* and one other :low detections without boost" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 500, 3_000, user_agent: nil),
          EB.burst({127, 0, 0, 1}, @base_ts, 400, 10)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:info, 500}, high_frequency_ip: {:low, 300}}
      assert score.score == 1
      assert score.total_events == 900
      assert score.total_findings == 2
    end

    test "produces :suspect score for detections with 1 < score <= 3" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 3_000, user_agent: "headlesschrome"),
          EB.burst({127, 0, 0, 1}, @base_ts, 400, 10,
            referer: "https://brandedleadgeneration.com"
          )
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :suspect

      assert score.rule_summary == %{
               spam_referer: {:low, 400},
               headless_browser: {:low, 10},
               high_frequency_ip: {:low, 300}
             }

      assert score.score == 5
      assert score.total_events == 410
      assert score.total_findings == 3
    end
  end

  describe "score/2 - total_events and evidence.event_count are different numbers" do
    test "for :session key" do
      events =
        EB.burst({127, 0, 0, 1}, @base_ts, 40, 10_000, user_agent: "test-velocity_ua") ++
          EB.burst({127, 0, 0, 1}, DateTime.add(@base_ts, 1, :hour), 10, 1_000,
            user_agent: "test-velocity_ua"
          )

      {:ok, [finding]} = Clickguard.detect(events, detectors: [Clickguard.Detector.ClickVelocity])

      assert [score] = Scorer.score([finding], Clickguard.actor_totals(events))
      assert score.total_events == 50
      assert finding.evidence.event_count == 10
    end
  end

  describe "score/2 - synthetic events" do
    test ":medium severity event produces Score with :fraud band and 3 score" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000)

      finding = %Finding{
        rule: :fake_medium_rule,
        severity: :medium,
        subject: "127.0.0.1",
        actor_type: :ip,
        evidence: %{
          event_count: 10,
          matched_values: ["val1", "val2"]
        },
        sample_events: Event.sample(events),
        detected_at: DateTime.now!("Etc/UTC")
      }

      assert [score] = Scorer.score([finding], Clickguard.actor_totals(events))
      assert score.band == :suspect
      assert score.rule_summary == %{fake_medium_rule: {:medium, 10}}
      assert score.score == 3
      assert score.total_events == 10
      assert score.total_findings == 1
    end

    test ":high severity event produces Score with :fraud band and 16 score" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000)

      finding = %Finding{
        rule: :fake_high_rule,
        severity: :high,
        subject: "127.0.0.1",
        actor_type: :ip,
        evidence: %{
          event_count: 10,
          matched_values: ["val1", "val2"]
        },
        sample_events: Event.sample(events),
        detected_at: DateTime.now!("Etc/UTC")
      }

      assert [score] = Scorer.score([finding], Clickguard.actor_totals(events))
      assert score.band == :fraud
      assert score.rule_summary == %{fake_high_rule: {:high, 10}}
      assert score.score == 16
      assert score.total_events == 10
      assert score.total_findings == 1
    end
  end
end
