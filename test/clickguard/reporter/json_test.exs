defmodule Clickguard.Reporter.JSONTest do
  alias Clickguard.{Reporter, Score}
  use ExUnit.Case, async: true

  @score_keys ["actor", "band", "rules", "score", "total_events", "total_findings"]
  @actor_keys ["type", "value"]
  @rule_keys ["event_count", "severity"]
  @rules [
    "high_detection",
    "low_detection",
    "medium_detection"
  ]

  describe "format/1" do
    test "structure is correct" do
      scores = [
        %Score{
          actor: {:ip, "127.0.0.1"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{low_detection: {:low, 1}},
          band: :clear,
          score: 1
        },
        %Score{
          actor: {:ip, "127.0.0.2"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{medium_detection: {:medium, 1}},
          band: :suspect,
          score: 3
        },
        %Score{
          actor: {:ip, "127.0.0.3"},
          total_findings: 1,
          total_events: 1,
          rule_summary: %{high_detection: {:high, 1}},
          band: :fraud,
          score: 16
        }
      ]

      parsed_data = scores |> Reporter.JSON.format() |> IO.iodata_to_binary() |> JSON.decode!()

      assert length(parsed_data) == 3

      Enum.each(parsed_data, fn obj ->
        assert Map.keys(obj) |> Enum.sort() == @score_keys
        assert Map.keys(obj["actor"]) |> Enum.sort() == @actor_keys

        Enum.each(obj["rules"], fn {key, values} ->
          assert key in @rules
          assert Map.keys(values) |> Enum.sort() == @rule_keys
        end)
      end)

      assert Map.fetch!(hd(parsed_data), "band") == "fraud"
      assert Map.fetch!(List.last!(parsed_data), "band") == "clear"
    end
  end
end
