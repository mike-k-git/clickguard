defmodule Clickguard.Detector.ClickVelocity do
  @moduledoc """
  Flags sessions that contain suspicious velocity patterns

  Rules (Subject = {IP, UA}):
    * :click_velocity - median interval within a session is below a threshold
                        and/or there is a event burst inside a second interval

  All `opts` are overridable. The minimum `min_session_clicks` is 2.

  `high_median_ms` and `burst_threshold` lead to :high severity; `medium_median_ms`
  to :medium.

  Severity: medium or high
  """
  alias Clickguard.{Event, Finding}
  @behaviour Clickguard.Detector

  @session_gap_ms 1_800_000
  @min_session_clicks 5
  @medium_median_ms 2_000
  @high_median_ms 1_000
  @burst_threshold 5

  @type evidence :: %{
          event_count: pos_integer(),
          sessions: [
            %{
              clicks: pos_integer(),
              median_delta_ms: float(),
              max_burst: pos_integer(),
              started_at: DateTime.t(),
              ended_at: DateTime.t()
            }
          ],
          median_delta_ms: float(),
          max_burst: pos_integer(),
          thresholds: map()
        }

  @impl true
  def name, do: :click_velocity

  @impl true
  def detect(events, opts) do
    detected_at = DateTime.now!("Etc/UTC")

    thresholds = %{
      session_gap_ms: Keyword.get(opts, :session_gap_ms, @session_gap_ms),
      min_session_clicks: max(Keyword.get(opts, :min_session_clicks, @min_session_clicks), 2),
      medium_median_ms: Keyword.get(opts, :medium_median_ms, @medium_median_ms),
      high_median_ms: Keyword.get(opts, :high_median_ms, @high_median_ms),
      burst_threshold: Keyword.get(opts, :burst_threshold, @burst_threshold)
    }

    events
    |> Enum.group_by(&Event.session_key/1)
    |> Enum.flat_map(fn {key, evs} ->
      evs
      |> Enum.sort_by(& &1.timestamp, DateTime)
      |> sessionize(thresholds)
      |> classify(key, thresholds, detected_at)
    end)
  end

  defp sessionize(events, thresholds) do
    chunk_fun = fn event, {session, prev_ts} ->
      if DateTime.after?(
           event.timestamp,
           DateTime.add(prev_ts, thresholds.session_gap_ms, :millisecond)
         ) do
        # current event is further than @session_gap_ms from previous
        # return accumulated events, pass current to new acc and its timestamp
        {:cont, Enum.reverse(session), {[event], event.timestamp}}
      else
        # current event within @session_gap_ms from previous
        # add it to the acc and update timestamp
        {:cont, {[event | session], event.timestamp}}
      end
    end

    after_fun = fn
      {session, _prev_ts} -> {:cont, Enum.reverse(session), []}
    end

    [first | rest] = events

    rest |> Enum.chunk_while({[first], first.timestamp}, chunk_fun, after_fun)
  end

  defp classify(sessions, key, thresholds, detected_at) do
    offenders =
      sessions
      |> Enum.filter(&(length(&1) >= thresholds.min_session_clicks))
      |> Enum.map(fn clicks ->
        intervals = click_intervals(clicks)
        median = median(intervals)
        max_burst = max_burst(clicks)

        %{clicks: clicks, median: median, max_burst: max_burst}
      end)
      |> Enum.filter(fn session ->
        session.median <= thresholds.medium_median_ms or
          session.max_burst >= thresholds.burst_threshold
      end)

    if offenders != [] do
      {worst, severity} = worst_session(offenders, thresholds)

      [
        %Finding{
          rule: :click_velocity,
          severity: severity,
          subject: key,
          actor_type: :session,
          evidence: build_evidence(offenders, worst, thresholds),
          sample_events: Event.sample(worst.clicks),
          detected_at: detected_at
        }
      ]
    else
      []
    end
  end

  defp worst_session(offenders, thresholds) do
    rank = fn s ->
      if s.median <= thresholds.high_median_ms or s.max_burst >= thresholds.burst_threshold,
        do: 2,
        else: 1
    end

    worst = Enum.max_by(offenders, &{rank.(&1), -&1.median})
    severity = if rank.(worst) == 2, do: :high, else: :medium

    {worst, severity}
  end

  defp max_burst(clicks) do
    clicks
    |> Enum.group_by(fn click ->
      {seconds, _ms} = DateTime.to_gregorian_seconds(click.timestamp)
      seconds
    end)
    |> Enum.map(fn {_seconds, clicks} -> length(clicks) end)
    |> Enum.max()
  end

  defp build_evidence(offenders, worst, thresholds) do
    evidence =
      offenders
      |> Enum.reduce(
        %{
          event_count: 0,
          sessions: [],
          median_delta_ms: worst.median,
          max_burst: worst.max_burst,
          thresholds: thresholds
        },
        fn %{clicks: clicks, median: median, max_burst: max_burst}, acc ->
          %{
            acc
            | event_count: acc.event_count + length(clicks),
              sessions: [
                %{
                  started_at: hd(clicks).timestamp,
                  ended_at: List.last(clicks).timestamp,
                  clicks: length(clicks),
                  median_delta_ms: median,
                  max_burst: max_burst
                }
                | acc.sessions
              ]
          }
        end
      )

    %{evidence | sessions: Enum.reverse(evidence.sessions)}
  end

  defp click_intervals(clicks) do
    clicks
    |> Enum.chunk_every(2, 1, :discard)
    |> Enum.map(fn [a, b] -> DateTime.diff(b.timestamp, a.timestamp, :millisecond) end)
  end

  defp median(intervals) do
    mid = div(length(intervals), 2)

    {i1, i2} = Enum.sort(intervals) |> Enum.split(mid)

    if length(i2) > length(i1) do
      [med | _] = i2
      med
    else
      [m1 | _] = i2
      [m2 | _] = Enum.reverse(i1)
      (m1 + m2) / 2
    end
  end
end
