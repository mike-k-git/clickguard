defmodule Clickguard.Detector.FreqIp do
  @moduledoc """
  Flag IPs with >N requests per minute over a sliding window.

  Returns the first window to cross the threshold, not the worst one in the batch.

  Severity: low
  """
  @behaviour Clickguard.Detector
  alias Clickguard.Event
  alias Clickguard.Finding

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
      if window = offending_window(evts, threshold, window_ms) do
        [build_finding(ip, window, window_ms, threshold, detected_at)]
      else
        []
      end
    end)
  end

  defp offending_window(events, threshold, window_ms) do
    events
    |> Enum.sort_by(& &1.timestamp)
    |> Enum.reduce_while(nil, fn event, acc ->
      {window, count} = acc || {:queue.new(), 0}
      cutoff = DateTime.add(event.timestamp, -window_ms, :millisecond)
      {pruned, pruned_count} = prune(&DateTime.before?(&1.timestamp, cutoff), window, count)
      new_window = :queue.in(event, pruned)
      new_count = pruned_count + 1

      if new_count >= threshold do
        {:halt, :queue.to_list(new_window)}
      else
        {:cont, {new_window, new_count}}
      end
    end)
    |> case do
      list when is_list(list) -> list
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

  defp build_finding(ip, window, window_ms, threshold, detected_at) do
    %Finding{
      rule: name(),
      severity: :low,
      subject: Event.format_ip(ip),
      evidence: %{count: length(window), threshold: threshold, window_ms: window_ms},
      sample_events: Enum.take(window, 5),
      detected_at: detected_at
    }
  end
end
