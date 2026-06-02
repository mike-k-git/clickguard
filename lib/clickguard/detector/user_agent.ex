defmodule Clickguard.Detector.UserAgent do
  @moduledoc """
  Flags requests by automated/headless user agents, keyed by IP.

  Rules (Subject = IP):
    * :empty_ua - UA nil/blank
    * :automation_tool - python-requests, curl, wget, Go-http-client, Scrapy
    * :headless_browser - HeadlessChrome, PhantomJS
    
  Catches lazy bots only - misses real-UA automation.
  A filter, strongest in combination, not a standalone verdict.

  Severity: low
  """
  @behaviour Clickguard.Detector
  alias Clickguard.{Event, Finding}

  @type evidence :: %{
          event_count: pos_integer(),
          matched_uas: [String.t()]
        }

  @automation ~w(python-requests curl wget go-http-client scrapy)
  @headless ~w(headlesschrome phantomjs)

  @impl true
  def name, do: :user_agent

  @impl true
  def detect(events, _opts) do
    detected_at = DateTime.now!("Etc/UTC")

    events
    |> Enum.flat_map(fn e ->
      case classify(e) do
        nil -> []
        rule -> [{{Event.ip_string(e), rule}, e}]
      end
    end)
    |> Enum.group_by(fn {key, _} -> key end, fn {_, e} -> e end)
    |> Enum.map(fn {{ip, rule}, evts} -> build_finding(rule, ip, evts, detected_at) end)
  end

  defp classify(%Event{user_agent: ua}) do
    if blank?(ua), do: :empty_ua, else: match_token(String.downcase(ua))
  end

  defp match_token(ua) do
    cond do
      contains_any?(ua, @automation) -> :automation_tool
      contains_any?(ua, @headless) -> :headless_browser
      true -> nil
    end
  end

  defp contains_any?(ua, tokens), do: Enum.any?(tokens, &String.contains?(ua, &1))

  defp build_finding(rule, ip, events, detected_at) do
    %Finding{
      rule: rule,
      severity: :low,
      subject: ip,
      evidence: build_evidence(events),
      sample_events: Event.sample(events),
      detected_at: detected_at
    }
  end

  defp build_evidence(events) do
    %{
      event_count: length(events),
      matched_uas: events |> Enum.map(& &1.user_agent) |> Enum.uniq() |> Enum.reject(&blank?/1)
    }
  end

  defp blank?(nil), do: true
  defp blank?(ua), do: String.trim(ua) == ""
end
