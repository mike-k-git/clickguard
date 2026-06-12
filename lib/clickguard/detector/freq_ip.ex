defmodule Clickguard.Detector.FreqIp do
  @moduledoc """
  Flag IPs with >N requests per minute over a sliding window.

  Returns the first window to cross the threshold, not the worst one in the batch.

  Severity: low
  """
  @behaviour Clickguard.Detector
  alias Clickguard.{Event, Finding}

  @type evidence :: %{
          event_count: pos_integer(),
          threshold: pos_integer(),
          window_ms: pos_integer(),
          window_start: DateTime.t(),
          window_end: DateTime.t()
        }

  @default_threshold 300
  @default_window_ms 60_000

  @impl true
  def name, do: :freq_ip

  @impl true
  def detect(events, opts) do
    threshold = Keyword.get(opts, :threshold, @default_threshold)
    window_ms = Keyword.get(opts, :window_ms, @default_window_ms)
    detected_at = DateTime.now!("Etc/UTC")

    events
    |> Enum.group_by(& &1.ip)
    |> Enum.flat_map(fn {ip, evts} ->
      case offending_window(evts, threshold, window_ms) do
        {window, count} -> [build_finding(ip, window, count, window_ms, threshold, detected_at)]
        nil -> []
      end
    end)
  end

  defp offending_window(events, threshold, window_ms) do
    result =
      events
      |> Enum.sort_by(& &1.timestamp, DateTime)
      |> Enum.reduce_while({:queue.new(), 0}, fn event, {window, count} ->
        cutoff = DateTime.add(event.timestamp, -window_ms, :millisecond)
        {pruned, pruned_count} = prune(&DateTime.before?(&1.timestamp, cutoff), window, count)
        new_window = :queue.in(event, pruned)
        new_count = pruned_count + 1

        if new_count >= threshold do
          {:halt, {:found, :queue.to_list(new_window), new_count}}
        else
          {:cont, {new_window, new_count}}
        end
      end)

    case result do
      {:found, list, count} -> {list, count}
      _ -> nil
    end
  end

  defp prune(fun, queue, count) do
    case :queue.peek(queue) do
      {:value, item} ->
        case fun.(item) do
          true ->
            prune(fun, :queue.drop(queue), count - 1)

          false ->
            {queue, count}
        end

      :empty ->
        {queue, count}
    end
  end

  defp build_finding(ip, window, count, window_ms, threshold, detected_at) do
    %Finding{
      rule: :high_frequency_ip,
      severity: :low,
      actor_type: :ip,
      subject: Event.format_ip(ip),
      evidence: build_evidence(window, count, threshold, window_ms),
      sample_events: Event.sample(window),
      detected_at: detected_at
    }
  end

  @spec build_evidence([Event.t()], pos_integer(), pos_integer(), pos_integer()) :: evidence()
  defp build_evidence(window, count, threshold, window_ms) do
    %{
      event_count: count,
      threshold: threshold,
      window_ms: window_ms,
      window_start: hd(window).timestamp,
      window_end: List.last(window).timestamp
    }
  end
end
