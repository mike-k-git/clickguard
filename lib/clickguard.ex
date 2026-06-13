defmodule Clickguard do
  @moduledoc """
  Reads a log file, parses each line into a `Clickguard.Event`, and runs
  the configured detectors over the resulting event list.

  Top-Level API is `run/2`.
  """

  alias Clickguard.{Event, Finding, Parser, Score, Scorer}

  @type opts :: [
          parser: module(),
          detectors: [module()]
        ]

  @doc """
  Parse input into events.
  """
  def parse(input, opts \\ []) do
    parser = Keyword.get(opts, :parser, Parser.CLF)

    {events, total, rejected} =
      input
      |> Stream.map(&String.trim_trailing/1)
      |> Stream.reject(&(&1 == ""))
      |> Enum.reduce({[], 0, 0}, fn line, {evs, tot, rej} ->
        case parser.parse(line) do
          {:ok, event} -> {[event | evs], tot + 1, rej}
          {:error, _} -> {evs, tot + 1, rej + 1}
        end
      end)

    if rejected > 0,
      do:
        IO.puts(
          :stderr,
          "clickguard: parsed #{total - rejected}/#{total} lines (#{rejected} rejected)"
        )

    {:ok, Enum.reverse(events)}
  end

  @doc """
  Run detectors over events.
  """
  @spec detect([Event.t()], opts()) :: {:ok, [Finding.t()]}
  def detect(events, opts \\ []) do
    detectors = Keyword.get(opts, :detectors, Application.get_env(:clickguard, :detectors, []))

    findings =
      detectors
      |> Task.async_stream(fn det -> det.detect(events, opts) end,
        ordered: false,
        timeout: :timer.minutes(5)
      )
      |> Enum.flat_map(fn {:ok, fs} -> fs end)

    {:ok, findings}
  end

  @spec actor_totals([Event.t()]) :: %{{atom(), String.t()} => non_neg_integer()}
  def actor_totals(events) do
    Enum.reduce(events, %{}, fn event, acc ->
      acc
      |> Map.update({:ip, Event.format_ip(event.ip)}, 1, &(&1 + 1))
      |> Map.update({:session, Event.session_key(event)}, 1, &(&1 + 1))
    end)
  end

  @doc """
  Run the full pipeline against a log file at `path` or from `:stdio`.

  Parse a log, run detectors, and emit a list of scores.
  """
  @spec run(Path.t() | Enumerable.t(), opts()) :: {:ok, [Score.t()]} | {:error, term()}
  def run(path, opts \\ [])
  def run(path, opts) when is_binary(path), do: run(File.stream!(path), opts)

  def run(input, opts) do
    {:ok, events} = parse(input, opts)
    {:ok, findings} = detect(events, opts)
    {:ok, Scorer.score(findings, actor_totals(events))}
  rescue
    e in File.Error -> {:error, to_string(:file.format_error(e.reason))}
  end
end
