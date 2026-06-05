defmodule Clickguard.CLI do
  @moduledoc """
  Handle the command line parsing and the dispatch to
  `Clickguard.run/1` and `Clickguard.Reporter.Text` that
  end up generating a formatted output.
  """
  alias Clickguard.Reporter.Text

  def main(args) do
    case OptionParser.parse(args, strict: []) do
      {_flags, [input_file], _} ->
        case Clickguard.run(input_file) do
          {:ok, scores} ->
            IO.write(Text.format(scores))

          {:error, reason} ->
            IO.puts(:stderr, "Error: " <> to_string(reason))
            System.halt(1)
        end

      _ ->
        IO.puts(:stderr, "Usage: clickguard input_log")
        System.halt(1)
    end
  end
end
