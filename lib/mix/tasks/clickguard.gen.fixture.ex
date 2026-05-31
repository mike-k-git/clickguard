defmodule Mix.Tasks.Clickguard.Gen.Fixture do
  @shortdoc "Generate a new fixture"
  @moduledoc """
  Generate a new fixture

  ## Command line options

    * `--lines`       - number of random generated events
    * `--out`         - path to the destination file
    * `--freqip`      - at least one `FreqIp` finding
    * `--bad-ua`      - at least one `UserAgent` finding
    * `--bad-referer` - at least one `Referer` finding

  """

  use Mix.Task

  @impl Mix.Task
  def run(args) do
    Mix.Project.get!()

    {opts, _, _} =
      OptionParser.parse(args,
        strict: [
          lines: :integer,
          out: :string,
          freqip: :boolean,
          bad_ua: :boolean,
          bad_referer: :boolean
        ]
      )

    {total, out} = Clickguard.Fixtures.generate(opts)
    Mix.shell().info("Wrote #{total} lines to #{out}")
  end
end
