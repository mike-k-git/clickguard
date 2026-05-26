defmodule Clickguard do
  @moduledoc """
  Reads a log file, parses each line into a `Clickguard.Event`, and runs
  the configured detectors over the resulting event list.

  Top-Level API is `run/2`.
  """

  alias Clickguard.{Finding, Parser}

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
  def detect(events, opts \\ []) do
    detectors = Keyword.get(opts, :detectors, Application.get_env(:clickguard, :detectors, []))

    detectors
    |> Task.async_stream(fn det -> det.detect(events, opts) end,
      ordered: false,
      timeout: :timer.minutes(5)
    )
    |> Enum.flat_map(fn {:ok, fs} -> fs end)
  end

  @doc """
  Run the full pipeline against a log file at `path`.

  Parse a log, run detectors, and emit a list of findings.
  """
  @spec run(Path.t(), opts()) :: {:ok, [Finding.t()]} | {:error, term()}
  def run(path, opts \\ []) do
    {:ok, events} = parse(File.stream!(path), opts)
    {:ok, detect(events, opts)}
  end
end
