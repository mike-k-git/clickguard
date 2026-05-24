defmodule Clickguard do
  @moduledoc """
  Reads a log stream, parses each line into a `Clickguard.Event`, runs
  every enabled detector over the resulting event set, and emits a
  `Clickguard.Report` containing the findings.

  Top-Level API is `run/2`; see `Clickguard.CLI` for the command-line
  interface.
  """

  alias Clickguard.{Event, Parser}

  @type opts :: [
          parser: module()
        ]

  @doc """
  Run the full pipeline against a log file at `path`.

  For the v0.1 milestone this just parses every line and returns a list of
  events. Detection and reporting wire in once those modules exist.

  ## Examples

    iex> path = "test/fixtures/sample_clf.log"
    iex> {:ok, events} = Clickguard.run(path)
    iex> is_list(events)
    iex> :ok
    :ok
  """
  @spec run(Path.t(), opts()) :: {:ok, [Event.t()]} | {:error, term()}
  def run(path, opts \\ []) do
    parser = Keyword.get(opts, :parser, Parser.CLF)

    case File.exists?(path) do
      false ->
        {:error, {:not_found, path}}

      true ->
        events =
          path
          |> File.stream!()
          |> Stream.map(&String.trim_trailing/1)
          |> Stream.reject(&(&1 == ""))
          |> Stream.map(&parser.parse/1)
          |> Stream.filter(&match?({:ok, _}, &1))
          |> Stream.map(fn {:ok, event} -> event end)
          |> Enum.to_list()

        {:ok, events}
    end
  end
end
