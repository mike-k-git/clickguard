defmodule Clickguard.Detector.Referer do
  @moduledoc """
  Flags requests with empty or known-spam referers, keyed by IP.

  Rules (Subject = IP):
    * :empty_referer - referer is nil/blank. Weak signal (privacy browsers,
      Referrer-Policy, HTTPS->HTTP downgrade all strip it legitimately).
      Has :info severity since intensity scoring introduction.
    * :spam_referer  - referer host matches a known referer-spam domain.

  Subject is uniformly the IP (symmetric with UserAgent). The domain-level
  view ("domain.com across N IPs") is recoverable vie a later group_by on
  evidence.matched_referers - deferred, not lost.

  Deferred (need deployment config): publisher mismatch, self-referencing loops.

  Severity: low
  """
  alias Clickguard.{Event, Finding}
  @behaviour Clickguard.Detector

  @type evidence :: %{
          event_count: pos_integer(),
          matched_referers: [String.t()]
        }

  @default_spam_domains ~w(
    brandedleadgeneration.com addshoppers.com 7minuteworkout.com
  )

  @impl true
  def name, do: :referer

  @impl true
  def detect(events, opts) do
    spam = Keyword.get(opts, :spam_domains, @default_spam_domains) |> MapSet.new()
    detected_at = DateTime.now!("Etc/UTC")

    events
    |> Enum.flat_map(fn e ->
      case classify(e, spam) do
        nil -> []
        {rule, value} -> [{{Event.ip_string(e), rule}, {e, value}}]
      end
    end)
    |> Enum.group_by(fn {key, _} -> key end, fn {_, pair} -> pair end)
    |> Enum.map(fn {{ip, rule}, pairs} -> build_finding(rule, ip, pairs, detected_at) end)
  end

  defp classify(%Event{referer: r}, spam) do
    if blank?(r), do: {:empty_referer, nil}, else: spam_match(r, spam)
  end

  defp spam_match(referer, spam) do
    case URI.parse(String.trim(referer)).host do
      nil ->
        nil

      host ->
        normalized = host |> String.downcase() |> String.replace_prefix("www.", "")
        if MapSet.member?(spam, normalized), do: {:spam_referer, normalized}, else: nil
    end
  end

  defp build_finding(rule, ip, pairs, detected_at) do
    events = Enum.map(pairs, fn {e, _} -> e end)

    severity = if rule == :empty_referer, do: :info, else: :low

    %Finding{
      rule: rule,
      severity: severity,
      subject: ip,
      actor_type: :ip,
      evidence: build_evidence(pairs),
      sample_events: Event.sample(events),
      detected_at: detected_at
    }
  end

  defp build_evidence(pairs) do
    %{
      event_count: length(pairs),
      matched_referers:
        pairs |> Enum.map(fn {_, v} -> v end) |> Enum.reject(&is_nil/1) |> Enum.uniq()
    }
  end

  defp blank?(nil), do: true
  defp blank?(r), do: String.trim(r) == ""
end
