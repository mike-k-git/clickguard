defmodule Clickguard.CLI do
  @moduledoc """
  Handle the command line parsing and the dispatch to
  `Clickguard.run/1` and appropriate `Clickguard.Reporter` that
  end up generating a formatted output.

  ## Usage

    ./clickguard events.log [options]
    cat events.log | ./clickguard [options]

  ## Options

    * `--format`  - Output format: text (default), json
    * `--fail-on` - Exit code control: findings of certain level change the exit code to 2.

  ## Examples
  """

  alias Clickguard.Reporter

  @known_flags ~w(--format --fail-on)
  @reporters %{"text" => Reporter.Text, "json" => Reporter.JSON}
  @fail_on_bands %{"suspect" => [:suspect, :fraud], "fraud" => [:fraud]}

  @success_code 0
  @error_code 1
  @fail_bands_code 2
  def main(args) do
    case run(args) do
      {:ok, output, @success_code} ->
        IO.write(output)

      {:ok, output, @fail_bands_code} ->
        IO.write(output)
        System.halt(@fail_bands_code)

      {:error, msg} ->
        IO.puts(:stderr, "clickguard: " <> msg)
        System.halt(@error_code)
    end
  end

  @spec run([String.t()], Enumerable.t()) ::
          {:ok, iodata(), non_neg_integer()} | {:error, String.t()}
  def run(args, stdin \\ IO.stream(:stdio, :line)) do
    with {:ok, input, reporter, fail_bands} <- parse_args(args, stdin),
         {:ok, scores} <- Clickguard.run(input) do
      output = reporter.format(scores)
      exit_code = if Enum.any?(scores, &(&1.band in fail_bands)), do: 2, else: 0
      {:ok, output, exit_code}
    end
  end

  defp parse_args(args, stdin) do
    {opts, positional, invalid} =
      OptionParser.parse(args, strict: [format: :string, fail_on: :string])

    with :ok <- check_invalid(invalid),
         {:ok, input} <- check_positional(positional, stdin),
         {:ok, reporter, fail_on_bands} <- build_opts(opts) do
      {:ok, input, reporter, fail_on_bands}
    end
  end

  defp check_invalid([]), do: :ok

  defp check_invalid([{flag, _} | _]) do
    if flag in @known_flags,
      do: {:error, "#{flag} requires a value"},
      else: {:error, "unknown option #{flag}"}
  end

  defp check_positional(positional, stdin) do
    case positional do
      [input] -> {:ok, input}
      [] -> {:ok, stdin}
      [_ | _] -> {:error, "too many positional arguments, expected exactly one input file"}
    end
  end

  defp build_opts(opts) do
    format = opts[:format] || "text"
    fail_on = opts[:fail_on]

    fail_on_bands =
      if fail_on, do: fetch_opt("--fail-on", fail_on, @fail_on_bands), else: {:ok, []}

    with {:ok, reporter} <- fetch_opt("--format", format, @reporters),
         {:ok, fail_on_bands} <- fail_on_bands do
      {:ok, reporter, fail_on_bands}
    end
  end

  defp fetch_opt(opt, key, values) do
    case Map.fetch(values, key) do
      {:ok, value} -> {:ok, value}
      :error -> {:error, "unknown value #{key} for option #{opt}"}
    end
  end
end
