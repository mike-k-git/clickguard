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

    events =
      input
      |> Stream.map(&String.trim_trailing/1)
      |> Stream.reject(&(&1 == ""))
      |> Stream.map(&parser.parse/1)
      |> Stream.filter(&match?({:ok, _}, &1))
      |> Stream.map(fn {:ok, event} -> event end)
      |> Enum.to_list()

    {:ok, events}
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

  @spec actor_totals([Event.t()]) :: %{String.t() => non_neg_integer()}
  def actor_totals(events) do
    Enum.frequencies_by(events, fn event -> Event.format_ip(event.ip) end)
  end

  @doc """
  Run the full pipeline against a log file at `path`.

  Parse a log, run detectors, and emit a list of scores.
  """
  @spec run(Path.t(), opts()) :: {:ok, [Score.t()]} | {:error, term()}
  def run(path, opts \\ []) do
    {:ok, events} = parse(File.stream!(path), opts)
    {:ok, findings} = detect(events, opts)
    {:ok, Scorer.score(findings, actor_totals(events))}
  rescue
    e in File.Error -> {:error, e.reason}
  end
end
