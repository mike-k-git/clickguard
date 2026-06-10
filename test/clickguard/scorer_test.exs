defmodule Clickguard.ScorerTest do
  use ExUnit.Case, async: true

  @base_ts ~U[2016-05-24 13:26:08.003Z]

  alias Clickguard.{Event, Finding, Scorer}
  alias Clickguard.EventBuilder, as: EB

  describe "score/2" do
    test "produces no scores without findings" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000)
      {:ok, findings} = Clickguard.detect(events, [])

      assert Scorer.score(findings, Clickguard.actor_totals(events)) == []
    end

    test "produces :clear score for :epmty_referer detection" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, referer: nil)
      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_referer: {:low, 10}}
      assert score.score == 0
      assert score.total_events == 10
      assert score.total_findings == 1
    end

    test "produces :clear score for :empty_ua detection" do
      events = EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: nil)
      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:low, 10}}
      assert score.score == 0
      assert score.total_events == 10
      assert score.total_findings == 1
    end

    test "produces :clear score for two distinct :empty_* detections" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: nil),
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, referer: nil)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:low, 10}, empty_referer: {:low, 10}}
      assert score.score == 0
      assert score.total_events == 20
      assert score.total_findings == 2
    end

    test "produces :clear score for one :empty_* and one other :low detections" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: nil),
          EB.burst({127, 0, 0, 1}, @base_ts, 400, 10)
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :clear
      assert score.rule_summary == %{empty_ua: {:low, 10}, high_frequency_ip: {:low, 300}}
      assert score.score == 1
      assert score.total_events == 410
      assert score.total_findings == 2
    end

    test "produces :suspect score for detections with 1 < score <= 3" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: "headlesschrome"),
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

      assert score.score == 3
      assert score.total_events == 410
      assert score.total_findings == 3
    end

    test "produces :fraud score for detections with score > 3" do
      events =
        [
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: "curl"),
          EB.burst({127, 0, 0, 1}, @base_ts, 10, 1_000, user_agent: "headlesschrome"),
          EB.burst({127, 0, 0, 1}, @base_ts, 400, 10,
            referer: "https://brandedleadgeneration.com"
          )
        ]
        |> List.flatten()

      {:ok, findings} = Clickguard.detect(events, [])

      assert [score] = Scorer.score(findings, Clickguard.actor_totals(events))
      assert score.actor == {:ip, "127.0.0.1"}
      assert score.band == :fraud

      assert score.rule_summary == %{
               spam_referer: {:low, 400},
               headless_browser: {:low, 10},
               automation_tool: {:low, 10},
               high_frequency_ip: {:low, 300}
             }

      assert score.score == 4
      assert score.total_events == 420
      assert score.total_findings == 4
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
