defmodule Clickguard.Parser do
  @moduledoc """
  Behaviour for log-line parsers.

  Implementations must return {:error, _} for lines with unparseable IPs.
  Emitting a nil-IP event is a contract violation.

  Implementations:

    * `Clickguard.Parser.CLF` - Apache/Nginx Combined Log Format
    * `Clickguard.Parser.AdLog` - ad-server JSON-lines (planned)

  ## Implementing a parser

    defmodule MyParser do
      @behaviour Clickguard.Parser
      alias Clickguard.Event

      @impl true
      def parse(line) do
        # ...
        {:ok, %Event{...}}
      end
    end
  """

  alias Clickguard.Event

  @type reason :: :empty | :malformed | {:bad_field, atom() | term()}

  @callback parse(line :: String.t()) :: {:ok, Event.t()} | {:error, reason()}
end
