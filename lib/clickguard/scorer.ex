defmodule Clickguard.Scorer do
  @moduledoc """
  Aggregates findings per actor and assigns a scored band.

  Bands: clear (score <= 1) / suspect (<= 3) / fraud (> 3)
  Rule weights: low = 1, medium = 3, high = 16
  Hygiene rules (:empty_ua, :empty_referer) carry weight 0.

  Band semantics:
    - clear   - at most one weak marker
    - suspect - accumulation of weak markers, or one behavioral medium
    - fraud   - behavioral signal + corroboration (medium + anything, or boosted medium),
                or extreme behavioral (high)

  Band cap: An actor whose findings are all `:low` severity does not exceed `:suspect`, regardless of score.
  Fraud requires at least one `:medium` or `:high` finding.

  Intensity boost: when a rule accounts for ≥50% of an actor's traffic and the actor has
  ≥20 events, its weight is doubled. FreqIp's event_count is the offending window only
  (understates on long logs); velocity's event_count is the whole offending session.
  """

  @min_sample 20
  @ratio_floor 0.5
  @boost 2

  alias Clickguard.{Finding, Score}

  @spec score([Finding.t()], map()) :: [Score.t()]
  def score(findings, total_by_actor) do
    findings
    |> Enum.group_by(fn %Finding{subject: subj, actor_type: a_type} -> {a_type, subj} end)
    |> Enum.map(fn {actor, actor_findings} ->
      summary = rule_summary(actor_findings)
      total = Map.fetch!(total_by_actor, actor)
      {band, score} = score_actor(summary, total)

      %Score{
        actor: actor,
        total_findings: length(actor_findings),
        total_events: total,
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

  defp score_actor(summary, total) do
    score =
      Enum.reduce(summary, 0, fn {_rule, {severity, count}}, acc ->
        acc + effective_weight(weight(severity), count, total)
      end)

    {cap(to_band(score), summary), score}
  end

  defp effective_weight(0, _count, _total), do: 0

  defp effective_weight(base, count, total)
       when total >= @min_sample and count / total >= @ratio_floor,
       do: base * @boost

  defp effective_weight(base, _count, _total), do: base

  defp weight(:info), do: 0
  defp weight(:low), do: 1
  defp weight(:medium), do: 3
  defp weight(:high), do: 16

  defp to_band(score) when score <= 1, do: :clear
  defp to_band(score) when score <= 3, do: :suspect
  defp to_band(_), do: :fraud

  defp cap(:fraud, summary) do
    if Enum.any?(summary, fn {_r, {sev, _}} -> sev in [:medium, :high] end),
      do: :fraud,
      else: :suspect
  end

  defp cap(band, _summary), do: band
end
