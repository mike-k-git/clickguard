defmodule Clickguard.Scorer do
  @moduledoc """
  Returns a list of `Clickguard.Score` aggregated by actor.
  """

  alias Clickguard.{Finding, Score}

  @spec score([Finding.t()], map()) :: [Score.t()]
  def score(findings, total_by_actor) do
    findings
    |> Enum.group_by(fn %Finding{subject: subj, actor_type: a_type} -> {a_type, subj} end)
    |> Enum.map(fn {actor, actor_findings} ->
      summary = rule_summary(actor_findings)
      {band, score} = score_actor(summary)

      %Score{
        actor: actor,
        total_findings: length(actor_findings),
        total_events: total_by_actor[actor],
        rule_summary: summary,
        band: band,
        score: score
      }
    end)
  end

  defp rule_summary(findings) do
    Enum.reduce(findings, %{}, fn finding, acc ->
      Map.update(
        acc,
        finding.rule,
        {finding.severity, finding.evidence.event_count},
        fn {severity, count} ->
          {severity, count + finding.evidence.event_count}
        end
      )
    end)
  end

  defp score_actor(rule_summary) do
    score =
      Enum.reduce(rule_summary, 0, fn {rule, {severity, _count}}, acc ->
        acc + weight(rule, severity)
      end)

    {to_band(score), score}
  end

  defp weight(rule, _severity) when rule in [:empty_ua, :empty_referer], do: 0
  defp weight(_rule, :low), do: 1
  defp weight(_rule, :medium), do: 3
  defp weight(_rule, :high), do: 16

  defp to_band(score) when score <= 1, do: :clear
  defp to_band(score) when score <= 3, do: :suspect
  defp to_band(_), do: :fraud
end
