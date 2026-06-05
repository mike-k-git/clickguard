defmodule Clickguard.Detector do
  @moduledoc """
  Behaviour for fraud detectors.

  Implementations:

    * `Clickguard.Detector.FreqIp` - IPs with >N requests per minute
    * `Clickguard.Detector.Referer` - empty or suspicious referers
    * `Clickguard.Detector.UserAgent` - match known datacenter/headless UAs

  ## Implementing a detector

    defmodule MyDetector do
      @behaviour Clickguard.Detector

      @impl true
      def name(), do: :detector_name

      @impl true
      def detect(events, opts) do
        # ...
        [%Finding{...}]
      end
    end
  """
  alias Clickguard.{Event, Finding}

  @callback name() :: atom()
  @callback detect(events :: [Event.t()], opts :: keyword()) :: [Finding.t()]
end
