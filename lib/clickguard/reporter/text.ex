defmodule Clickguard.Reporter.Text do
  @moduledoc """
  Generates plain text output from a list of `Clickguard.Score`.

  Output is sorted by `band`, from the most severe to the least.
  """
  alias Clickguard.Reporter
  @behaviour Clickguard.Reporter

  @severity_rank %{high: 0, medium: 1, low: 2}

  @impl true
  def format(scores) do
    header = ["actor\tevents\tband\tscore\tsummary\tworst\n"]

    rows =
      scores
      |> Reporter.sort()
      |> Enum.map(fn score ->
        {actor_type, actor} = score.actor

        [
          to_string(actor_type),
          ":",
          actor,
          "\t",
          Integer.to_string(score.total_events),
          "\t",
          to_string(score.band),
          "\t",
          Integer.to_string(score.score),
          "\t",
          severity_summary(score.rule_summary),
          "\t",
          worst_rule(score.rule_summary),
          "\n"
        ]
      end)

    [header | rows]
  end

  defp severity_summary(rule_summary) do
    rule_summary
    |> Enum.frequencies_by(fn {_rule, {severity, _count}} -> severity end)
    |> Enum.sort_by(fn {severity, _count} -> Map.get(@severity_rank, severity, 99) end)
    |> Enum.map(fn {severity, count} ->
      [to_string(severity), ": ", Integer.to_string(count)]
    end)
    |> Enum.intersperse(", ")
  end

  defp worst_rule(rule_summary) do
    [{rule, {_severity, count}}] =
      rule_summary
      |> Enum.sort_by(fn {_rule, {severity, count}} ->
        {Map.get(@severity_rank, severity, 99), -count}
      end)
      |> Enum.take(1)

    [":", to_string(rule), " (", Integer.to_string(count), ")"]
  end
end
