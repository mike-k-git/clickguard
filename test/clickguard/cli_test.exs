defmodule Clickguard.CLITest do
  use ExUnit.Case, async: true

  @clean ~s(test/fixtures/clean.log)
  @suspect ~s(test/fixtures/suspect.log)
  @fraud ~s(test/fixtures/fraud.log)

  describe "CLI.run/1 - formats" do
    test "text output is correct" do
      args = [@suspect]

      {:ok, output, exit_code} = Clickguard.CLI.run(args)
      assert exit_code == 0

      [header, l1 | _] = output |> IO.iodata_to_binary() |> String.split("\n", trim: true)
      assert header == "actor\tevents\tband\tscore\tsummary\tworst"
      assert String.contains?(l1, "suspect")
    end

    test "text output without scores contains only header" do
      args = [@clean]

      {:ok, output, exit_code} = Clickguard.CLI.run(args)
      assert exit_code == 0

      [header] = output |> IO.iodata_to_binary() |> String.split("\n", trim: true)
      assert header == "actor\tevents\tband\tscore\tsummary\tworst"
    end

    test "text output with is correct when option is set explicitly" do
      args = [@clean, "--format", "text"]

      {:ok, output, exit_code} = Clickguard.CLI.run(args)
      assert exit_code == 0

      [header] = output |> IO.iodata_to_binary() |> String.split("\n", trim: true)
      assert header == "actor\tevents\tband\tscore\tsummary\tworst"
    end

    test "json output is correct" do
      args = [@suspect, "--format", "json"]

      {:ok, output, exit_code} = Clickguard.CLI.run(args)
      assert exit_code == 0

      parsed_data = output |> IO.iodata_to_binary() |> JSON.decode!()
      assert is_list(parsed_data)
      assert parsed_data != []
      assert Map.has_key?(hd(parsed_data), "band")
    end

    test "json output without scores contains empty array" do
      args = [@clean, "--format", "json"]

      {:ok, output, exit_code} = Clickguard.CLI.run(args)
      assert exit_code == 0

      parsed_data = output |> IO.iodata_to_binary() |> JSON.decode!()
      assert is_list(parsed_data)
      assert parsed_data == []
    end
  end

  describe "CLI.run/1 - exit codes" do
    test "no --fail-on flag -> 0" do
      args = [@fraud]
      {:ok, _output, 0} = Clickguard.CLI.run(args)
    end

    test "--fail-on 'fraud' flag without fraud scores -> 0" do
      args = [@suspect, "--fail-on", "fraud"]
      {:ok, _output, 0} = Clickguard.CLI.run(args)
    end

    test "--fail-on 'fraud' flag with fraud scores -> 2" do
      args = [@fraud, "--fail-on", "fraud"]
      {:ok, _output, 2} = Clickguard.CLI.run(args)
    end

    test "--fail-on 'suspect' flag with fraud or suspect scores -> 2" do
      args = [@fraud, "--fail-on", "suspect"]
      {:ok, _output, 2} = Clickguard.CLI.run(args)
    end
  end

  describe "CLI.run/1 - errors" do
    test "unknown format" do
      args = [@clean, "--format", "unknown"]
      {:error, "unknown value unknown for option --format"} = Clickguard.CLI.run(args)
    end

    test "unknown --fail-on value" do
      args = [@clean, "--fail-on", "unknown"]
      {:error, "unknown value unknown for option --fail-on"} = Clickguard.CLI.run(args)
    end

    test "unknown flag" do
      args = [@clean, "--foo"]
      {:error, "unknown option --foo"} = Clickguard.CLI.run(args)
    end

    test "nonexistent path" do
      args = ["nonexistent"]
      {:error, "no such file or directory"} = Clickguard.CLI.run(args)
    end

    test "two positional arguments" do
      args = [@clean, @suspect]

      {:error, "too many positional arguments, expected exactly one input file"} =
        Clickguard.CLI.run(args)
    end
  end
end
