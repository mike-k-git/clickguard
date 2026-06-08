defmodule Clickguard.Reporter.JSON do
  @moduledoc """
  Generates JSON from `Clickguard.Score`.
  The output is an array where each score is a separate object.

  Output is sorted by `band`, from the most severe to the least.
  """
  alias Clickguard.Reporter
  @behaviour Clickguard.Reporter

  @impl true
  def format(scores) do
    scores
    |> Reporter.sort()
    |> Enum.map(&to_map/1)
    |> JSON.encode_to_iodata!()
  end

  defp to_map(score) do
    {actor_type, actor_value} = score.actor

    rules =
      Map.new(score.rule_summary, fn {rule, {severity, event_count}} ->
        {rule, %{severity: severity, event_count: event_count}}
      end)

    %{
      actor: %{type: actor_type, value: actor_value},
      band: score.band,
      score: score.score,
      total_events: score.total_events,
      total_findings: score.total_findings,
      rules: rules
    }
  end
end
