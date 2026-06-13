defmodule Mix.Tasks.Clickguard.Gen.Fixture do
  @shortdoc "Generate a new fixture"
  @moduledoc """
  Generate a new fixture

  ## Command line options

    * `--lines`           - number of random generated events
    * `--out`             - path to the destination file
    * `--freqip`          - at least one `FreqIp` finding
    * `--bad-ua`          - at least one `UserAgent` finding
    * `--bad-referer`     - at least one `Referer` finding
    * `--velocity`        - at least one `ClickVelocity` finding
    * `--velocity-medium` - generates two medium `ClickVelocity' findings, one of which is boosted
    * `--velocity-mixed`  - generates one `ClickVelocity` burst and many one event sessions to lower ratio

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
          bad_referer: :boolean,
          velocity: :boolean,
          velocity_medium: :boolean,
          velocity_mixed: :boolean
        ]
      )

    {total, out} = Clickguard.Fixtures.generate(opts)
    Mix.shell().info("Wrote #{total} lines to #{out}")
  end
end
