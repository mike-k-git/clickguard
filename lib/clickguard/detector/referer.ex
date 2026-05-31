defmodule Clickguard.Detector.Referer do
  @moduledoc """
  Surfaces requests with empty or known-spam referers

  Rules:
    * :empty_referer - referer is nil/blank. Weak signal (privacy browsers,
      Referrer-Policy, HTTPS->HTTP downgrade all strip it legitimately).
    * :spam_referer  - referer host matches a known referer-spam domain.
      Subject is the matched domain.

  NOTE: subject semantics differ by rule (sentinel vs domain). Never reason
  about a referer finding's subject without branching on :rule.

  Deferred (need deployment config): publisher mismatch, self-referencing loops.

  Severity: low
  """
  alias Clickguard.{Event, Finding}
  @behaviour Clickguard.Detector

  @type evidence :: %{
          event_count: pos_integer(),
          ips: [String.t()],
          ips_truncated: boolean(),
          matched_value: String.t() | nil
        }

  @empty_subject "(none)"

  @default_spam_domains ~w(
    brandedleadgeneration.com addshoppers.com 7minuteworkout.com
  )

  @impl true
  def name, do: :referer

  @impl true
  def detect(events, opts) do
    spam = Keyword.get(opts, :spam_domains, @default_spam_domains) |> MapSet.new()
    detected_at = DateTime.now!("Etc/UTC")

    empty_findings(events, detected_at) ++ spam_findings(events, spam, detected_at)
  end

  defp empty_findings(events, detected_at) do
    case Enum.filter(events, &blank_referer?/1) do
      [] -> []
      evts -> [build_finding(:empty_referer, @empty_subject, nil, evts, detected_at)]
    end
  end

  defp spam_findings(events, spam, detected_at) do
    events
    |> Enum.flat_map(fn e ->
      case spam_host(e, spam) do
        nil ->
          []

        host ->
          [{host, e}]
      end
    end)
    |> Enum.group_by(fn {host, _} -> host end, fn {_, e} -> e end)
    |> Enum.map(fn {host, evts} ->
      build_finding(:spam_referer, host, host, evts, detected_at)
    end)
  end

  defp build_finding(rule, subject, matched, evts, detected_at) do
    ips = evts |> Enum.map(&Event.ip_string/1) |> Enum.uniq() |> Enum.reject(&is_nil/1)

    %Finding{
      rule: rule,
      severity: :low,
      subject: subject,
      evidence: %{
        event_count: length(evts),
        ips: ips |> Enum.take(50),
        ips_truncated: length(ips) > 50,
        matched_value: matched
      },
      sample_events: Event.sample(evts),
      detected_at: detected_at
    }
  end

  defp blank_referer?(%Event{referer: nil}), do: true
  defp blank_referer?(%Event{referer: r}), do: String.trim(r) == ""

  defp spam_host(%Event{referer: r}, _spam) when is_nil(r), do: nil

  defp spam_host(%Event{referer: r}, spam) do
    case String.trim(r) do
      "" -> nil
      trimmed -> match_host(URI.parse(trimmed).host, spam)
    end
  end

  defp match_host(nil, _spam), do: nil

  defp match_host(host, spam) do
    normalized =
      String.downcase(host)
      |> String.replace_prefix("www.", "")

    if MapSet.member?(spam, normalized), do: normalized, else: nil
  end
end
